<?php
/**
 * Copyright (c) 2012 Bart Visscher <bartv@thisnet.nl>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus;

use OCA\Files_Antivirus\Scanner\ScannerFactory;
use OCP\Files\File;
use OCP\Files\IMimeTypeLoader;
use OCP\IDBConnection;
use OCP\IL10N;
use OCP\Files\IRootFolder;
use OCP\ILogger;
use OCP\IUser;
use OCP\IUserManager;

class BackgroundScanner {

	const BATCH_SIZE = 10;

	/** @var IRootFolder */
	protected $rootFolder;

	/** @var ScannerFactory */
	private $scannerFactory;

	/** @var IL10N */
	private $l10n;

	/** @var  AppConfig  */
	private $appConfig;

	/** @var ILogger */
	protected $logger;

	/** @var IUserManager */
	protected $userManager;

	/** @var IDBConnection */
	protected $db;

	/** @var IMimeTypeLoader */
	protected $mimeTypeLoader;

	/** @var ItemFactory */
	protected $itemFactory;

	/**
	 * A constructor
	 *
	 * @param ScannerFactory $scannerFactory
	 * @param IL10N $l10n
	 * @param AppConfig $appConfig
	 * @param IRootFolder $rootFolder
	 * @param ILogger $logger
	 * @param IUserManager $userManager
	 * @param IDBConnection $db
	 * @param IMimeTypeLoader $mimeTypeLoader
	 * @param ItemFactory $itemFactory
	 */
	public function __construct(ScannerFactory $scannerFactory,
								IL10N $l10n,
								AppConfig $appConfig,
								IRootFolder $rootFolder,
								ILogger $logger,
								IUserManager $userManager,
								IDBConnection $db,
								IMimeTypeLoader $mimeTypeLoader,
								ItemFactory $itemFactory
	){
		$this->rootFolder = $rootFolder;
		$this->scannerFactory = $scannerFactory;
		$this->l10n = $l10n;
		$this->appConfig = $appConfig;
		$this->logger = $logger;
		$this->userManager = $userManager;
		$this->db = $db;
		$this->mimeTypeLoader = $mimeTypeLoader;
		$this->itemFactory = $itemFactory;
	}
	
	/**
	 * Background scanner main job
	 */
	public function run(){
		// locate files that are not checked yet
		try {
			$result = $this->getFilesForScan();
		} catch(\Exception $e) {
			$this->logger->error( __METHOD__ . ', exception: ' . $e->getMessage(), ['app' => 'files_antivirus']);
			return;
		}

		$cnt = 0;
		while (($row = $result->fetch()) && $cnt < self::BATCH_SIZE) {
			try {
				$fileId = $row['fileid'];
				$userId = $row['user_id'];
				/** @var IUser $owner */
				$owner = $this->userManager->get($userId);
				if (!$owner instanceof IUser){
					continue;
				}
				$this->scanOneFile($owner, $fileId);
				// increased only for successfully scanned files
				$cnt = $cnt + 1;
			} catch (\Exception $e) {
				$this->logger->error( __METHOD__ . ', exception: ' . $e->getMessage(), ['app' => 'files_antivirus']);
			}
		}
	}

	protected function getFilesForScan(){
		$dirMimeTypeId = $this->mimeTypeLoader->getId('httpd/unix-directory');

		$qb = $this->db->getQueryBuilder();

		$sizeLimit = (int)$this->appConfig->getAvMaxFileSize();
		if ( $sizeLimit === -1 ){
			$sizeLimitExpr = $qb->expr()->neq('fc.size', $qb->expr()->literal('0'));
		} else {
			$sizeLimitExpr = $qb->expr()->andX(
				$qb->expr()->neq('fc.size', $qb->expr()->literal('0')),
				$qb->expr()->lt('fc.size', $qb->createNamedParameter($sizeLimit))
			);
		}

		$qb->select(['fc.fileid', 'mnt.user_id'])
			->from('filecache', 'fc')
			->leftJoin('fc', 'files_antivirus', 'fa', $qb->expr()->eq('fa.fileid', 'fc.fileid'))
			->innerJoin(
				'fc',
				'mounts',
				'mnt',
				$qb->expr()->andX(
					$qb->expr()->eq('fc.storage', 'mnt.storage_id')
				)
			)
			->where(
				$qb->expr()->neq('fc.mimetype', $qb->expr()->literal($dirMimeTypeId))
			)
			->andWhere(
				$qb->expr()->orX(
					$qb->expr()->isNull('fa.fileid'),
					$qb->expr()->gt('fc.mtime', 'fa.check_time')
				)
			)
			->andWhere(
				$qb->expr()->like('fc.path', $qb->expr()->literal('files/%'))
			)
			->andWhere( $sizeLimitExpr )
		;
		return $qb->execute();
	}

	/**
	 * @param IUser $owner
	 * @param int $fileId
	 */
	protected function scanOneFile(IUser $owner, $fileId){
		$userFolder = $this->rootFolder->getUserFolder($owner->getUID());
		$files = $userFolder->getById($fileId);

		if (count($files) === 0) {
			return;
		}

		/** @var File $file */
		$file = array_pop($files);

		if (!($file instanceof File)) {
			return;
		}

		$item = $this->itemFactory->newItem($file);
		$scanner = $this->scannerFactory->getScanner();
		$status = $scanner->scan($item);
		$status->dispatch($item, true);
	}
}
