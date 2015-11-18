<?php
/**
 * Copyright (c) 2012 Bart Visscher <bartv@thisnet.nl>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus;

use OCP\IUserManager;
use OCP\IL10N;

use OCA\Files_Antivirus\Item;

class BackgroundScanner {

	/**
	 * @var ScannerFactory
	 */
	private $scannerFactory;
	
	/**
	 * @var IUserManager 
	 */
	private $userManager;
	
	/**
	 * @var IL10N
	 */
	private $l10n;
	
	/**
	 * A constructor
	 * @param \OCA\Files_Antivirus\ScannerFactory $scannerFactory
	 * @param IUserManager $userManager
	 * @param IL10N $l10n
	 */
	public function __construct(ScannerFactory $scannerFactory, IUserManager $userManager, IL10N $l10n){
		$this->scannerFactory = $scannerFactory;
		$this->userManager = $userManager;
		$this->l10n = $l10n;
	}
	
	/**
	 * Background scanner main job
	 * @return null
	 */
	public function run(){
		if (!$this->initFS()) {
			return;
		}
		// locate files that are not checked yet
		$dirMimetypeId = \OC::$server->getMimeTypeLoader()->getId('httpd/unix-directory');
		$sql = 'SELECT `*PREFIX*filecache`.`fileid`, `*PREFIX*storages`.*'
			.' FROM `*PREFIX*filecache`'
			.' LEFT JOIN `*PREFIX*files_antivirus` ON `*PREFIX*files_antivirus`.`fileid` = `*PREFIX*filecache`.`fileid`'
			.' JOIN `*PREFIX*storages` ON `*PREFIX*storages`.`numeric_id` = `*PREFIX*filecache`.`storage`'
			.' WHERE `mimetype` != ?'
			.' AND (`*PREFIX*storages`.`id` LIKE ? OR `*PREFIX*storages`.`id` LIKE ?)'
			.' AND (`*PREFIX*files_antivirus`.`fileid` IS NULL OR `mtime` > `check_time`)'
			.' AND `path` LIKE ?'
			.' AND `*PREFIX*filecache`.`size` != 0';
		$stmt = \OCP\DB::prepare($sql, 5);
		try {
			$result = $stmt->execute(array($dirMimetypeId, 'local::%', 'home::%', 'files/%'));
			if (\OCP\DB::isError($result)) {
				\OCP\Util::writeLog('files_antivirus', __METHOD__. 'DB error: ' . \OCP\DB::getErrorMessage($result), \OCP\Util::ERROR);
				return;
			}
		} catch(\Exception $e) {
			\OCP\Util::writeLog('files_antivirus', __METHOD__.', exception: '.$e->getMessage(), \OCP\Util::ERROR);
			return;
		}
	
		$view = new \OC\Files\View('/');
		while ($row = $result->fetchRow()) {
			$path = $view->getPath($row['fileid']);
			if (!is_null($path)) {
				$item = new Item($this->l10n, $view, $path, $row['fileid']);
				$scanner = $this->scannerFactory->getScanner();
				$status = $scanner->scan($item);					
				$status->dispatch($item, true);
			}
		}
		\OC_Util::tearDownFS();
	}
	
	/**
	 * A hack to access files and views. Better than before.
	 */
	protected function initFS(){
		//Need any valid user to mount FS
		$results = $this->userManager->search('', 2, 0);
		$anyUser = array_pop($results);
		if (is_null($anyUser)) {
			\OCP\Util::writeLog('files_antivirus', "Failed to setup file system", \OCP\Util::ERROR);
			return false;
		}
		\OC_Util::tearDownFS();
		\OC_Util::setupFS($anyUser->getUID());
		return true;
	}

	
	/**
	 * @deprecated 
	 */
	public static function check(){
		return \OCA\Files_Antivirus\Cron\Task::run();
	}
}
