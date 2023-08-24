<?php

declare(strict_types=1);
/**
 * Copyright (c) 2012 Bart Visscher <bartv@thisnet.nl>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\BackgroundJob;

use OCA\Files_Antivirus\AppConfig;
use OCA\Files_Antivirus\Event\BeforeBackgroundScanEvent;
use OCA\Files_Antivirus\ItemFactory;
use OCA\Files_Antivirus\Scanner\ScannerFactory;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\TimedJob;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Files\Config\IUserMountCache;
use OCP\Files\File;
use OCP\Files\IMimeTypeLoader;
use OCP\Files\IRootFolder;
use OCP\Files\Node;
use OCP\IDBConnection;
use Psr\Log\LoggerInterface;

class BackgroundScanner extends TimedJob {
	protected IRootFolder $rootFolder;
	private ScannerFactory $scannerFactory;
	private AppConfig $appConfig;
	protected LoggerInterface $logger;
	protected IDBConnection $db;
	protected IMimeTypeLoader $mimeTypeLoader;
	protected ItemFactory $itemFactory;
	private IUserMountCache $userMountCache;
	private IEventDispatcher $eventDispatcher;
	private bool $isCLI;

	public function __construct(
		ITimeFactory $timeFactory,
		ScannerFactory $scannerFactory,
		AppConfig $appConfig,
		IRootFolder $rootFolder,
		LoggerInterface $logger,
		IDBConnection $db,
		IMimeTypeLoader $mimeTypeLoader,
		ItemFactory $itemFactory,
		IUserMountCache $userMountCache,
		IEventDispatcher $eventDispatcher,
		bool $isCLI
	) {
		parent::__construct($timeFactory);
		$this->rootFolder = $rootFolder;
		$this->scannerFactory = $scannerFactory;
		$this->appConfig = $appConfig;
		$this->logger = $logger;
		$this->db = $db;
		$this->mimeTypeLoader = $mimeTypeLoader;
		$this->itemFactory = $itemFactory;
		$this->userMountCache = $userMountCache;
		$this->eventDispatcher = $eventDispatcher;
		$this->isCLI = $isCLI;

		// Run once per 15 minutes
		$this->setInterval(60 * 15);
	}

	/**
	 * Background scanner main job
	 */
	public function run($argument): void {
		if ($this->appConfig->getAppValue('av_background_scan') !== 'on') {
			// Background checking disabled no need to continue
			$this->logger->debug('Antivirus background scan disabled, skipping');
			return;
		}
		$remaining = $this->getBatchSize();
		$this->scan($remaining);
	}

	public function scan(int $max): int {
		$count = 0;
		// locate files that are not checked yet
		try {
			$unscanned = $this->getUnscannedFiles();
		} catch (\Exception $e) {
			$this->logger->error($e->getMessage(), ['exception' => $e]);
			return 0;
		}

		$unscanned = new \LimitIterator($unscanned, 0, $max);
		$this->logger->debug('Start background scan');

		// Run for unscanned files
		$count += $this->processFiles($unscanned);

		if ($count >= $max) {
			// we are done
			return $count;
		}

		// Run for updated files
		try {
			$rescan = $this->getToRescanFiles();
		} catch (\Exception $e) {
			$this->logger->error($e->getMessage(), ['exception' => $e]);
			return $count;
		}

		$rescan = new \LimitIterator($rescan, 0, $max - $count);
		$count += $this->processFiles($rescan);

		if ($count >= $max) {
			// we are done
			return $count;
		}

		// Run for files that have been scanned in the past. Just start to rescan them as the virus definitions might have been updated
		try {
			$outdated = $this->getOutdatedFiles();
		} catch (\Exception $e) {
			$this->logger->error($e->getMessage(), ['exception' => $e]);
			return $count;
		}

		$outdated = new \LimitIterator($outdated, 0, $max - $count);
		$this->processFiles($outdated);

		return $count;
	}

	/**
	 * @param iterable<int> $fileIds
	 * @return int
	 */
	private function processFiles(iterable $fileIds): int {
		$count = 0;
		foreach ($fileIds as $fileId) {
			try {
				$file = $this->getNodeForFile($fileId);
				if ($file instanceof File) {
					$this->scanOneFile($file);
					// increased only for successfully scanned files
					$count++;
				} else {
					$this->logger->info('Tried to scan non file');
				}
			} catch (\Exception $e) {
				$this->logger->error(__METHOD__ . ', exception: ' . $e->getMessage(), ['app' => 'files_antivirus', 'exception' => $e]);
			}
		}
		return $count;
	}

	public function getNodeForFile(int $fileId): ?Node {
		$cachedMounts = $this->userMountCache->getMountsForFileId($fileId);

		foreach ($cachedMounts as $cachedMount) {
			$userFolder = $this->rootFolder->getUserFolder($cachedMount->getUser()->getUID());
			$nodes = $userFolder->getById($fileId);
			foreach ($nodes as $node) {
				if ($node->isReadable()) {
					return $node;
				}
			}
		}
		return null;
	}

	public function getBatchSize(): int {
		$batchSize = 10;
		if ($this->isCLI) {
			$batchSize = 100;
		}

		$this->logger->debug('Batch size is: ' . $batchSize);

		return $batchSize;
	}

	protected function getSizeLimitExpression(IQueryBuilder $qb) {
		$sizeLimit = $this->appConfig->getAvMaxFileSize();
		if ($sizeLimit === -1) {
			$sizeLimitExpr = $qb->expr()->neq('fc.size', $qb->expr()->literal('0'));
		} else {
			$sizeLimitExpr = $qb->expr()->andX(
				$qb->expr()->neq('fc.size', $qb->expr()->literal('0')),
				$qb->expr()->lt('fc.size', $qb->createNamedParameter($sizeLimit))
			);
		}

		return $sizeLimitExpr;
	}

	/**
	 * @return \Iterator<int>
	 * @throws \OCP\DB\Exception
	 */
	public function getUnscannedFiles() {
		$dirMimeTypeId = $this->mimeTypeLoader->getId('httpd/unix-directory');

		$query = $this->db->getQueryBuilder();
		$query->select('fc.fileid')
			->from('filecache', 'fc')
			->leftJoin('fc', 'files_antivirus', 'fa', $query->expr()->eq('fc.fileid', 'fa.fileid'))
			->where($query->expr()->isNull('fa.fileid'))
			->andWhere($query->expr()->neq('mimetype', $query->expr()->literal($dirMimeTypeId)))
			->andWhere($query->expr()->like('path', $query->expr()->literal('files/%')))
			->andWhere($this->getSizeLimitExpression($query))
			->setMaxResults($this->getBatchSize() * 10);

		$result = $query->executeQuery();
		while (($fileId = $result->fetchOne()) !== false) {
			yield (int)$fileId;
		}
	}


	/**
	 * @return \Iterator<int>
	 * @throws \OCP\DB\Exception
	 */
	public function getToRescanFiles() {
		$qb = $this->db->getQueryBuilder();
		$qb->select('fc.fileid')
			->from('filecache', 'fc')
			->join('fc', 'files_antivirus', 'fa', $qb->expr()->eq('fc.fileid', 'fa.fileid'))
			->andWhere($qb->expr()->lt('fa.check_time', 'fc.mtime'))
			->andWhere($this->getSizeLimitExpression($qb))
			->setMaxResults($this->getBatchSize() * 10);

		$result = $qb->executeQuery();
		while (($fileId = $result->fetchOne()) !== false) {
			yield (int)$fileId;
		}
	}


	/**
	 * @return \Iterator<int>
	 * @throws \OCP\DB\Exception
	 */
	public function getOutdatedFiles() {
		$dirMimeTypeId = $this->mimeTypeLoader->getId('httpd/unix-directory');

		// We do not want to keep scanning the same files. So only scan them once per 28 days at most.
		$yesterday = time() - (28 * 24 * 60 * 60);

		$query = $this->db->getQueryBuilder();
		$query->select('fc.fileid')
			->from('filecache', 'fc')
			->innerJoin('fc', 'files_antivirus', 'fa', $query->expr()->eq('fc.fileid', 'fa.fileid'))
			->andWhere($query->expr()->neq('mimetype', $query->createNamedParameter($dirMimeTypeId)))
			->andWhere($query->expr()->like('path', $query->expr()->literal('files/%')))
			->andWhere($query->expr()->lt('check_time', $query->createNamedParameter($yesterday)))
			->andWhere($this->getSizeLimitExpression($query))
			->setMaxResults($this->getBatchSize() * 10);

		$result = $query->executeQuery();
		while (($fileId = $result->fetchOne()) !== false) {
			yield (int)$fileId;
		}
	}

	protected function scanOneFile(File $file): void {
		$this->logger->debug('Scanning file with fileid: ' . $file->getId());
		$this->eventDispatcher->dispatchTyped(new BeforeBackgroundScanEvent($file));

		$item = $this->itemFactory->newItem($file, true);
		$scanner = $this->scannerFactory->getScanner();
		$status = $scanner->scan($item);
		$status->dispatch($item);
	}
}
