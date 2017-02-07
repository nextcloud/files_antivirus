<?php
/**
 * Copyright (c) 2012 Bart Visscher <bartv@thisnet.nl>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus;

use Doctrine\DBAL\Platforms\MySqlPlatform;
use OC\Files\Filesystem;
use OCP\IL10N;
use OCP\Files\IRootFolder;
use OCP\IUser;
use OCP\IUserSession;

class BackgroundScanner {

	const BATCH_SIZE = 10;

	/** @var IRootFolder */
	protected $rootFolder;

	/** @var \OCP\Files\Folder[] */
	protected $userFolders;

	/** @var ScannerFactory */
	private $scannerFactory;

	/** @var IL10N */
	private $l10n;

	/** @var  AppConfig  */
	private $appConfig;

	/** @var string */
	protected $currentFilesystemUser;

	/** @var \OCP\IUserSession */
	protected $userSession;

	/**
	 * A constructor
	 *
	 * @param \OCA\Files_Antivirus\ScannerFactory $scannerFactory
	 * @param IL10N $l10n
	 * @param AppConfig $appConfig
	 * @param IRootFolder $rootFolder
	 * @param IUserSession $userSession
	 */
	public function __construct(ScannerFactory $scannerFactory,
								IL10N $l10n,
								AppConfig $appConfig,
								IRootFolder $rootFolder,
								IUserSession $userSession
	){
		$this->rootFolder = $rootFolder;
		$this->scannerFactory = $scannerFactory;
		$this->l10n = $l10n;
		$this->appConfig = $appConfig;
		$this->userSession = $userSession;
	}
	
	/**
	 * Background scanner main job
	 * @return null
	 */
	public function run(){
		// locate files that are not checked yet
		try {
			$result = $this->getFilesForScan();
		} catch(\Exception $e) {
			\OC::$server->getLogger()->error( __METHOD__ . ', exception: ' . $e->getMessage(), ['app' => 'files_antivirus']);
			return;
		}

		$cnt = 0;
		while (($row = $result->fetch()) && $cnt < self::BATCH_SIZE) {
			try {
				$fileId = $row['fileid'];
				$userId = $row['user_id'];
				/** @var IUser $owner */
				$owner = \OC::$server->getUserManager()->get($userId);
				if (!$owner instanceof IUser){
					continue;
				}
				$this->scanOneFile($owner, $fileId);
				// increased only for successfully scanned files
				$cnt = $cnt + 1;
			} catch (\Exception $e){
				\OC::$server->getLogger()->error( __METHOD__ . ', exception: ' . $e->getMessage(), ['app' => 'files_antivirus']);
			}
		}
		$this->tearDownFilesystem();
	}

	protected function getFilesForScan(){
		$dirMimeTypeId = \OC::$server->getMimeTypeLoader()->getId('httpd/unix-directory');

		$dbConnection = \OC::$server->getDatabaseConnection();
		$qb = $dbConnection->getQueryBuilder();
		if ($dbConnection->getDatabasePlatform() instanceof MySqlPlatform) {
			$concatFunction = $qb->createFunction(
				"CONCAT('/', mnt.user_id, '/')"
			);
		} else {
			$concatFunction = $qb->createFunction(
				"'/' || " . $qb->getColumnName('mnt.user_id') . " || '/')"
			);
		}

		$sizeLimit = intval($this->appConfig->getAvMaxFileSize());
		if ( $sizeLimit === -1 ){
			$sizeLimitExpr = $qb->expr()->neq('fc.size', $qb->expr()->literal('0'));
		} else {
			$sizeLimitExpr = $qb->expr()->andX(
				$qb->expr()->neq('fc.size', $qb->expr()->literal('0')),
				$qb->expr()->lt('fc.size', $qb->expr()->literal((string) $sizeLimit))
			);
		}

		$qb->select(['fc.fileid, mnt.user_id'])
			->from('filecache', 'fc')
			->leftJoin('fc', 'files_antivirus', 'fa', $qb->expr()->eq('fa.fileid', 'fc.fileid'))
			->innerJoin(
				'fc',
				'mounts',
				'mnt',
				$qb->expr()->andX(
					$qb->expr()->eq('fc.storage', 'mnt.storage_id'),
					$qb->expr()->eq('mnt.mount_point', $concatFunction)
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
	protected function scanOneFile($owner, $fileId){
		$this->initFilesystemForUser($owner);
		$view = Filesystem::getView();
		$path = $view->getPath($fileId);
		if (!is_null($path)) {
			$item = new Item($this->l10n, $view, $path, $fileId);
			$scanner = $this->scannerFactory->getScanner();
			$status = $scanner->scan($item);
			$status->dispatch($item, true);
		}
	}

	/**
	 * @param \OCP\IUser $user
	 * @return \OCP\Files\Folder
	 */
	protected function getUserFolder(IUser $user) {
		if (!isset($this->userFolders[$user->getUID()])) {
			$userFolder = $this->rootFolder->getUserFolder($user->getUID());
			$this->userFolders[$user->getUID()] = $userFolder;
		}
		return $this->userFolders[$user->getUID()];
	}

	/**
	 * @param IUser $user
	 */
	protected function initFilesystemForUser(IUser $user) {
		if ($this->currentFilesystemUser !== $user->getUID()) {
			if ($this->currentFilesystemUser !== '') {
				$this->tearDownFilesystem();
			}
			Filesystem::init($user->getUID(), '/' . $user->getUID() . '/files');
			$this->userSession->setUser($user);
			$this->currentFilesystemUser = $user->getUID();
			Filesystem::initMountPoints($user->getUID());
		}
	}

	/**
	 *
	 */
	protected function tearDownFilesystem(){
		$this->userSession->setUser(null);
		\OC_Util::tearDownFS();
	}

	/**
	 * @deprecated since  v8.0.0
	 */
	public static function check(){
	}
}
