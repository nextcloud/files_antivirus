<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus;

use OC\Files\View;
use OCP\App;
use OCP\IL10N;

class Item implements IScannable{
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
	
	public function __construct(IL10N $l10n, View $view, $path, $id = null) {
		$this->l10n = $l10n;
		
		if (!is_object($view)){
			$this->logError('Can\'t init filesystem view.', $id, $path);
			throw new \RuntimeException();
		}
		
		if(!$view->file_exists($path)) {
			$this->logError('File does not exist.', $id, $path);
			throw new \RuntimeException();
		}

		$this->id = $id;
		if (is_null($id)){
			$this->id = $view->getFileInfo($path)->getId();
		}

		$this->view = $view;
		$this->path = $path;
		
		$this->isValidSize = $view->filesize($path) > 0;
		
		$application = new AppInfo\Application();
		$config = $application->getContainer()->query(AppConfig::class);
		$this->chunkSize = $config->getAvChunkSize();
	}
	
	/**
	 * Is this file good for scanning? 
	 * @return boolean
	 */
	public function isValid() {
		return !$this->view->is_dir($this->path) && $this->isValidSize;
	}
	
	/**
	 * Reads a file portion by portion until the very end
	 * @return string|boolean
	 */
	public function fread() {
		if (!$this->isValid()) {
			return false;
		}
		if (is_null($this->fileHandle)) {
			$this->getFileHandle();
		}
		
		if (!is_null($this->fileHandle) && !$this->feof()) {
			return fread($this->fileHandle, $this->chunkSize);
		}
		return false;
	}
	
	/**
	 * Action to take if this item is infected
	 * @param Status $status
	 * @param boolean $isBackground
	 */
	public function processInfected(Status $status, $isBackground) {
		$application = new AppInfo\Application();
		$appConfig = $application->getContainer()->query('AppConfig');
		$infectedAction = $appConfig->getAvInfectedAction();
		
		$shouldDelete = !$isBackground || ($isBackground && $infectedAction === 'delete');
		
		$message = $shouldDelete ? Activity::MESSAGE_FILE_DELETED : '';

		$activityManager = \OC::$server->getActivityManager();
		$activity = $activityManager->generateEvent();
		$activity->setApp('files_antivirus')
			->setSubject(Activity::SUBJECT_VIRUS_DETECTED, [$this->path, $status->getDetails()])
			->setMessage($message)
			->setObject('', 0, $this->path)
			->setAffectedUser($this->view->getOwner($this->path))
			->setType(Activity::TYPE_VIRUS_DETECTED);
		$activityManager->publish($activity);

		if ($isBackground) {
			if ($shouldDelete) {
				$this->logError('Infected file deleted. ' . $status->getDetails());
				$this->deleteFile();
			} else {
				$this->logError('File is infected. '  . $status->getDetails());
			}
		} else {
			$this->logError('Virus(es) found: ' . $status->getDetails());
			//remove file
			$this->deleteFile();
			Notification::sendMail($this->path);
			$message = $this->l10n->t(
						"Virus detected! Can't upload the file %s", 
						[basename($this->path)]
			);
			\OCP\JSON::error(['data' => ['message' => $message]]);
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
			$result = $stmt->execute([$this->id]);
			if (\OCP\DB::isError($result)) {
				//TODO: Use logger
				$this->logError(__METHOD__. ', DB error: ' . \OCP\DB::getErrorMessage());
			}
			$stmt = \OCP\DB::prepare('INSERT INTO `*PREFIX*files_antivirus` (`fileid`, `check_time`) VALUES (?, ?)');
			$result = $stmt->execute([$this->id, time()]);
			if (\OCP\DB::isError($result)) {
				$this->logError(__METHOD__. ', DB error: ' . \OCP\DB::getErrorMessage());
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
		$fileHandle = $this->view->fopen($this->path, 'r');
		if ($fileHandle === false) {
			$this->logError('Can not open for reading.', $this->id, $this->path);
			throw new \RuntimeException();
		}

		$this->logDebug('Scan started');
		$this->fileHandle = $fileHandle;
	}

	/**
	 * Delete infected file
	 */
	private function deleteFile() {
		//prevent from going to trashbin
		if (App::isEnabled('files_trashbin')) {
			\OCA\Files_Trashbin\Storage::preRenameHook([]);
		}
		$this->view->unlink($this->path);
		if (App::isEnabled('files_trashbin')) {
			\OCA\Files_Trashbin\Storage::postRenameHook([]);
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
