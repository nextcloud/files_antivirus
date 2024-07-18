<?php

declare(strict_types=1);
/**
 * Copyright (c) 2012 Bart Visscher <bartv@thisnet.nl>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\BackgroundJob;

use Doctrine\DBAL\Driver\ResultStatement;
use OCA\Files_Antivirus\AppConfig;
use OCA\Files_Antivirus\ItemFactory;
use OCA\Files_Antivirus\Scanner\ScannerFactory;
use OCP\BackgroundJob\TimedJob;
use OCP\DB\IResult;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\Files\File;
use OCP\Files\FileInfo;
use OCP\Files\IMimeTypeLoader;
use OCP\Files\IRootFolder;
use OCP\IDBConnection;
use OCP\IUser;
use OCP\IUserManager;
use Psr\Log\LoggerInterface;

class BackgroundScanner extends TimedJob {
	protected IRootFolder $rootFolder;
	private ScannerFactory $scannerFactory;
	private AppConfig $appConfig;
	protected LoggerInterface $logger;
	protected IUserManager $userManager;
	protected IDBConnection $db;
	protected IMimeTypeLoader $mimeTypeLoader;
	protected ItemFactory $itemFactory;
	private bool $isCLI;

	public function __construct(
		ScannerFactory $scannerFactory,
		AppConfig $appConfig,
		IRootFolder $rootFolder,
		LoggerInterface $logger,
		IUserManager $userManager,
		IDBConnection $db,
		IMimeTypeLoader $mimeTypeLoader,
		ItemFactory $itemFactory,
		bool $isCLI
	) {
		$this->rootFolder = $rootFolder;
		$this->scannerFactory = $scannerFactory;
		$this->appConfig = $appConfig;
		$this->logger = $logger;
		$this->userManager = $userManager;
		$this->db = $db;
		$this->mimeTypeLoader = $mimeTypeLoader;
		$this->itemFactory = $itemFactory;
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
			$this->logger->debug('Antivirus background scan disablled, skipping');
			return;
		}

		// locate files that are not checked yet
		try {
			$result = $this->getUnscannedFiles();
		} catch (\Exception $e) {
			$this->logger->error($e->getMessage(), ['exception' => $e]);
			return;
		}

		$this->logger->debug('Start background scan');
		$batchSize = $this->getBatchSize();

		// Run for unscanned files
		$cnt = 0;
		while (($row = $result->fetch()) && $cnt < $batchSize) {
			try {
				$fileId = $row['fileid'];
				$users = $this->getUserWithAccessToStorage((int)$row['storage']);

				foreach ($users as $user) {
					/** @var IUser $owner */
					$owner = $this->userManager->get($user['user_id']);
					if (!$owner instanceof IUser) {
						continue;
					}

					$userFolder = $this->rootFolder->getUserFolder($owner->getUID());
					$files = $userFolder->getById($fileId);

					if ($files === []) {
						continue;
					}

					$file = array_pop($files);
					if ($file instanceof File) {
						if ($userFolder->nodeExists($userFolder->getRelativePath($file->getPath()))) {
							$this->scanOneFile($file);
						}
					} else {
						$this->logger->error('Tried to scan non file');
					}

					// increased only for successfully scanned files
					$cnt++;
					break;
				}
			} catch (\Exception $e) {
				$this->logger->error($e->getMessage(), ['exception' => $e]);
			}
		}

		if ($cnt === $batchSize) {
			// we are done
			return;
		}

		// Run for updated files
		try {
			$result = $this->getToRescanFiles();
		} catch (\Exception $e) {
			$this->logger->error($e->getMessage(), ['exception' => $e]);
			return;
		}

		while (($row = $result->fetch()) && $cnt < $batchSize) {
			try {
				$fileId = $row['fileid'];
				$users = $this->getUserWithAccessToStorage((int)$row['storage']);

				foreach ($users as $user) {
					/** @var IUser $owner */
					$owner = $this->userManager->get($user['user_id']);
					if (!$owner instanceof IUser) {
						continue;
					}

					$userFolder = $this->rootFolder->getUserFolder($owner->getUID());
					$files = $userFolder->getById($fileId);

					if ($files === []) {
						continue;
					}

					$file = array_pop($files);

					if ($file instanceof File) {
						if ($userFolder->nodeExists($userFolder->getRelativePath($file->getPath()))) {
							$this->scanOneFile($file);
						}
					} else {
						$this->logger->error('Tried to scan non file');
					}

					// increased only for successfully scanned files
					$cnt++;
					break;
				}
			} catch (\Exception $e) {
				$this->logger->error(__METHOD__ . ', exception: ' . $e->getMessage(), ['app' => 'files_antivirus']);
			}
		}


		// Run for files that have been scanned in the past. Just start to rescan them as the virus definitaions might have been updated
		try {
			$result = $this->getOutdatedFiles();
		} catch (\Exception $e) {
			$this->logger->error($e->getMessage(), ['exception' => $e]);
			return;
		}

		while (($row = $result->fetch()) && $cnt < $batchSize) {
			try {
				$fileId = $row['fileid'];
				$users = $this->getUserWithAccessToStorage((int)$row['storage']);

				foreach ($users as $user) {
					/** @var IUser $owner */
					$owner = $this->userManager->get($user['user_id']);
					if (!$owner instanceof IUser) {
						continue;
					}

					$userFolder = $this->rootFolder->getUserFolder($owner->getUID());
					$files = $userFolder->getById($fileId);

					if ($files === []) {
						continue;
					}

					$file = array_pop($files);
					if ($file instanceof File) {
						if ($userFolder->nodeExists($userFolder->getRelativePath($file->getPath()))) {
							$this->scanOneFile($file);
						}
					} else {
						$this->logger->error('Tried to scan non file');
					}

					// increased only for successfully scanned files
					$cnt++;
					break;
				}
			} catch (\Exception $e) {
				$this->logger->error(__METHOD__ . ', exception: ' . $e->getMessage(), ['app' => 'files_antivirus']);
			}
		}
	}

	protected function getBatchSize(): int {
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

	protected function getUserWithAccessToStorage(int $storageId): array {
		$qb = $this->db->getQueryBuilder();

		$qb->select('user_id')
			->from('mounts')
			->where($qb->expr()->eq('storage_id', $qb->createNamedParameter($storageId)));

		$cursor = $qb->execute();
		/** @psalm-suppress UndefinedInterfaceMethod */
		return $cursor->fetchAll();
	}

	public function getUnscannedFiles() {
		$dirMimeTypeId = $this->mimeTypeLoader->getId(FileInfo::MIMETYPE_FOLDER);

		$query = $this->db->getQueryBuilder();
		$query->select('fc.fileid', 'storage')
			->from('filecache', 'fc')
			->leftJoin('fc', 'storages', 's', $query->expr()->eq('fc.storage', 's.numeric_id'))
			->leftJoin('fc', 'files_antivirus', 'fa', $query->expr()->eq('fc.fileid', 'fa.fileid'))
			->where($query->expr()->isNull('fa.fileid'))
			->andWhere($query->expr()->neq('mimetype', $query->createNamedParameter($dirMimeTypeId)))
			->andWhere($query->expr()->orX(
				$query->expr()->like('path', $query->createNamedParameter('files/%')),
				$query->expr()->notLike('s.id', $query->createNamedParameter("home::%"))
			))
			->andWhere($this->getSizeLimitExpression($query))
			->setMaxResults($this->getBatchSize() * 10);

		return $query->execute();
	}

	protected function getToRescanFiles() {
		$qb = $this->db->getQueryBuilder();
		$qb->select('fc.fileid', 'fc.storage')
			->from('filecache', 'fc')
			->join('fc', 'files_antivirus', 'fa', $qb->expr()->eq('fc.fileid', 'fa.fileid'))
			->andWhere($qb->expr()->lt('fa.check_time', 'fc.mtime'))
			->andWhere($this->getSizeLimitExpression($qb))
			->setMaxResults($this->getBatchSize() * 10);

		return $qb->execute();
	}

	public function getOutdatedFiles() {
		$dirMimeTypeId = $this->mimeTypeLoader->getId('httpd/unix-directory');

		// We do not want to keep scanning the same files. So only scan them once per 28 days at most.
		$yesterday = time() - (28 * 24 * 60 * 60);

		$query = $this->db->getQueryBuilder();
		$query->select('fc.fileid', 'fc.storage')
			->from('filecache', 'fc')
			->innerJoin('fc', 'files_antivirus', 'fa', $query->expr()->eq('fc.fileid', 'fa.fileid'))
			->andWhere($query->expr()->neq('mimetype', $query->createNamedParameter($dirMimeTypeId)))
			->andWhere($query->expr()->like('path', $query->expr()->literal('files/%')))
			->andWhere($query->expr()->lt('check_time', $query->createNamedParameter($yesterday)))
			->andWhere($this->getSizeLimitExpression($query))
			->setMaxResults($this->getBatchSize() * 10);

		return $query->execute();
	}

	protected function scanOneFile(File $file): void {
		$this->logger->debug('Scanning file with fileid: ' . $file->getId());

		$item = $this->itemFactory->newItem($file, true);
		$scanner = $this->scannerFactory->getScanner();
		$status = $scanner->scan($item);
		$status->dispatch($item);
	}
}
