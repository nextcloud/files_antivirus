<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus;

use OCP\IL10N;
use OCA\Files_Antivirus\Status;
use OCA\Files_Antivirus\Activity;

class Item implements iScannable{
	/**
	 * Scanned fileid (optional)
	 * @var int
	 */
	protected $id;
	
	/**
	 * File view
	 * @var \OC\Files\View
	 */
	protected $view;
	
	/**
	 * Path relative to the view
	 * @var string
	 */
	protected $path;
	
	/**
	 * file handle, user to read from the file
	 * @var resource
	 */
	protected $fileHandle;
	
	/**
	 * Portion size
	 * @var int
	 */
	protected $chunkSize;
	
	/**
	 * Is filesize match the size conditions
	 * @var bool
	 */
	protected $isValidSize;
	
	/**
	 * @var IL10N
	 */
	private $l10n;
	
	public function __construct(IL10N $l10n, $view, $path, $id = null) {
		$this->l10n = $l10n;
		
		if (!is_object($view)){
			$this->logError('Can\'t init filesystem view.', $id, $path);
			throw new \RuntimeException();
		}
		
		if(!$view->file_exists($path)) {
			$this->logError('File does not exist.', $id, $path);
			throw new \RuntimeException();
		}
		
		if (is_null($id)){
			$this->id = $view->getFileInfo($path)->getId();
		} else {
			$this->id = $id;
		}
		
		$this->view = $view;
		$this->path = $path;
		
		$this->isValidSize = $view->filesize($path) > 0;
		
		$application = new \OCA\Files_Antivirus\AppInfo\Application();
		$config = $application->getContainer()->query('AppConfig');
		$this->chunkSize = $config->getAvChunkSize();
	}
	
	/**
	 * Is this file good for scanning? 
	 * @return boolean
	 */
	public function isValid() {
		$isValid = !$this->view->is_dir($this->path) && $this->isValidSize;
		return $isValid;
	}
	
	/**
	 * Reads a file portion by portion until the very end
	 * @return string|boolean
	 */
	public function fread() {
		if (!$this->isValid()) {
			return;
		}
		if (is_null($this->fileHandle)) {
			$this->getFileHandle();
		}
		
		if (!is_null($this->fileHandle) && !$this->feof()) {
			$chunk = fread($this->fileHandle, $this->chunkSize);
			return $chunk;
		}
		return false;
	}
	
	/**
	 * Action to take if this item is infected
	 * @param Status $status
	 * @param boolean $isBackground
	 */
	public function processInfected(Status $status, $isBackground) {
		$application = new \OCA\Files_Antivirus\AppInfo\Application();
		$appConfig = $application->getContainer()->query('AppConfig');
		$infectedAction = $appConfig->getAvInfectedAction();
		
		$shouldDelete = !$isBackground || ($isBackground && $infectedAction === 'delete');
		
		$message = $shouldDelete ? Activity::MESSAGE_FILE_DELETED : '';
		
		\OC::$server->getActivityManager()->publishActivity(
					'files_antivirus',
					Activity::SUBJECT_VIRUS_DETECTED,
					array($this->path, $status->getDetails()),
					$message,
					array(),
					$this->path, 
					'', 
					$this->view->getOwner($this->path),
					Activity::TYPE_VIRUS_DETECTED, 
					Activity::PRIORITY_HIGH
				);
		if ($isBackground) {
			if ($shouldDelete) {
				$this->logError('Infected file deleted. ' . $status->getDetails());
				$this->view->unlink($this->path);
			} else {
				$this->logError('File is infected. '  . $status->getDetails());
			}
		} else {
			$this->logError('Virus(es) found: ' . $status->getDetails());
			//remove file
			$this->view->unlink($this->path);
			Notification::sendMail($this->path);
			$message = $this->l10n->t(
						"Virus detected! Can't upload the file %s", 
						array(basename($this->path))
			);
			\OCP\JSON::error(array("data" => array( "message" => $message)));
			exit();
		}
	}

	/**
	 * Action to take if this item status is unclear
	 * @param Status $status
	 * @param boolean $isBackground
	 */
	public function processUnchecked(Status $status, $isBackground) {
		//TODO: Show warning to the user: The file can not be checked
		$this->logError('Not Checked. ' . $status->getDetails());
	}
	
	/**
	 * Action to take if this item status is not infected
	 * @param Status $status
	 * @param boolean $isBackground
	 */
	public function processClean(Status $status, $isBackground) {
		if (!$isBackground) {
			return;
		}
		try {
			$stmt = \OCP\DB::prepare('DELETE FROM `*PREFIX*files_antivirus` WHERE `fileid` = ?');
			$result = $stmt->execute(array($this->id));
			if (\OCP\DB::isError($result)) {
				//TODO: Use logger
				$this->logError(__METHOD__. ', DB error: ' . \OCP\DB::getErrorMessage($result));
			}
			$stmt = \OCP\DB::prepare('INSERT INTO `*PREFIX*files_antivirus` (`fileid`, `check_time`) VALUES (?, ?)');
			$result = $stmt->execute(array($this->id, time()));
			if (\OCP\DB::isError($result)) {
				$this->logError(__METHOD__. ', DB error: ' . \OCP\DB::getErrorMessage($result));
			}
		} catch(\Exception $e) {
			\OCP\Util::writeLog('files_antivirus', __METHOD__.', exception: '.$e->getMessage(), \OCP\Util::ERROR);
		}
	}

	/**
	 * Check if the end of file is reached
	 * @return boolean
	 */
	private function feof() {
		$isDone = feof($this->fileHandle);
		if ($isDone) {
			$this->logDebug('Scan is done');
			fclose($this->fileHandle);
			$this->fileHandle = null;
		}
		return $isDone;
	}
	
	/**
	 * Opens a file for reading
	 * @throws \RuntimeException
	 */
	private function getFileHandle() {
		$fileHandle = $this->view->fopen($this->path, "r");
		if ($fileHandle === false) {
			$this->logError('Can not open for reading.', $this->id, $this->path);
			throw new \RuntimeException();
		} else {
			$this->logDebug('Scan started');
			$this->fileHandle = $fileHandle;
		}
	}
	
	/**
	 * @param string $message
	 */
	public function logDebug($message) {
		$extra = ' File: ' . $this->id 
				. 'Account: ' . $this->view->getOwner($this->path) 
				. ' Path: ' . $this->path;
		\OCP\Util::writeLog('files_antivirus', $message . $extra, \OCP\Util::DEBUG);
	}
	
	/**
	 * @param string $message
	 * @param int $id optional
	 * @param string $path optional
	 */
	public function logError($message, $id=null, $path=null) {
		$ownerInfo = is_null($this->view) ? '' : 'Account: ' . $this->view->getOwner($path);
		$extra = ' File: ' . (is_null($id) ? $this->id : $id)
				. $ownerInfo 
				. ' Path: ' . (is_null($path) ? $this->path : $path);
		\OCP\Util::writeLog(
				'files_antivirus',
				$message . $extra,
				\OCP\Util::ERROR
		);
	}
}
