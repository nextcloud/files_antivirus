<?php
/**
 * Copyright (c) 2012 Bart Visscher <bartv@thisnet.nl>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus;

use OC\Files\Filesystem;
use OC\Files\View;
use OCP\IL10N;
use OCP\IUser;
use OCP\Files\IRootFolder;
use OCP\IUserSession;

class BackgroundScanner {

	const BATCH_SIZE = 10;

	/** @var IRootFolder */
	protected $rootFolder;

	/** @var \OCP\Files\Folder[] */
	protected $userFolders;

	/**
	 * @var ScannerFactory
	 */
	private $scannerFactory;

	
	/**
	 * @var IL10N
	 */
	private $l10n;

	/** @var string */
	protected $currentFilesystemUser;

	/** @var \OCP\IUserSession */
	protected $userSession;

	/**
	 * A constructor
	 *
	 * @param \OCA\Files_Antivirus\ScannerFactory $scannerFactory
	 * @param IL10N $l10n
	 * @param IRootFolder $rootFolder
	 * @param IUserSession $userSession
	 */
	public function __construct(ScannerFactory $scannerFactory,
								IL10N $l10n,
								IRootFolder $rootFolder,
								IUserSession $userSession
	){
		$this->rootFolder = $rootFolder;
		$this->scannerFactory = $scannerFactory;
		$this->l10n = $l10n;
		$this->userSession = $userSession;
	}
	
	/**
	 * Background scanner main job
	 * @return null
	 */
	public function run(){
		// locate files that are not checked yet
		$dirMimeTypeId = \OC::$server->getMimeTypeLoader()->getId('httpd/unix-directory');
		try {
			$qb = \OC::$server->getDatabaseConnection()->getQueryBuilder();
			$qb->select(['fc.fileid'])
				->from('filecache', 'fc')
				->leftJoin('fc', 'files_antivirus', 'fa', $qb->expr()->eq('fa.fileid', 'fc.fileid'))
				->innerJoin(
					'fc',
					'storages',
					'ss',
					$qb->expr()->andX(
						$qb->expr()->eq('fc.storage', 'ss.numeric_id'),
						$qb->expr()->orX(
							$qb->expr()->like('ss.id', $qb->expr()->literal('local::%')),
							$qb->expr()->like('ss.id', $qb->expr()->literal('home::%'))
						)
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
				->andWhere(
					$qb->expr()->neq('fc.size', $qb->expr()->literal('0'))
				)
				->setMaxResults(self::BATCH_SIZE)
			;
			$result = $qb->execute();
		} catch(\Exception $e) {
			\OC::$server->getLogger()->error( __METHOD__ . ', exception: ' . $e->getMessage(), ['app' => 'files_antivirus']);
			return;
		}

		try {
			while ($row = $result->fetch()) {
				$fileId = $row['fileid'];
				$owner = $this->getOwner($fileId);
				if (!$owner){
					continue;
				}
				$this->initFilesystemForUser($owner);
				$view = \OC\Files\Filesystem::getView();
				$path = $view->getPath($fileId);
				if (!is_null($path)) {
					$item = new Item($this->l10n, $view, $path, $fileId);
					$scanner = $this->scannerFactory->getScanner();
					$status = $scanner->scan($item);
					$status->dispatch($item, true);
				}
			}
		} catch (\Exception $e){
			\OC::$server->getLogger()->error( __METHOD__ . ', exception: ' . $e->getMessage(), ['app' => 'files_antivirus']);
		}
		\OC_Util::tearDownFS();
	}

	protected function getOwner($fileId){
		$mountProviderCollection = \OC::$server->getMountProviderCollection();
		$mountCache = $mountProviderCollection->getMountCache();
		$mounts = $mountCache->getMountsForFileId($fileId);
		if (!empty($mounts)) {
			$user = $mounts[0]->getUser();
			if ($user instanceof IUser) {
				return $user;
			}
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
				Filesystem::tearDown();
			}
			Filesystem::init($user->getUID(), '/' . $user->getUID() . '/files');
			$this->userSession->setUser($user);
			$this->currentFilesystemUser = $user->getUID();
			\OC\Files\Filesystem::initMountPoints($user->getUID());
		}
	}

	/**
	 * @deprecated since  v8.0.0
	 */
	public static function check(){
	}
}
