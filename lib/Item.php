<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus;

use OCA\Files_Antivirus\Activity\Provider;
use OCA\Files_Antivirus\AppInfo\Application;
use OCA\Files_Antivirus\Db\ItemMapper;
use OCP\Activity\IManager as ActivityManager;
use OCP\App;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\Files\File;
use OCP\IL10N;
use OCP\ILogger;

class Item implements IScannable{
	/**
	 * file handle, user to read from the file
	 * @var resource
	 */
	protected $fileHandle;

	/** @var IL10N */
	private $l10n;

	/** @var AppConfig */
	private $config;

	/** @var ActivityManager */
	private $activityManager;

	/** @var ItemMapper */
	private $itemMapper;

	/** @var ILogger */
	private $logger;

	/** @var File */
	private $file;

	public function __construct(IL10N $l10n,
								AppConfig $appConfig,
								ActivityManager $activityManager,
								ItemMapper $itemMapper,
								ILogger $logger,
								File $file) {
		$this->l10n = $l10n;
		$this->config = $appConfig;
		$this->activityManager = $activityManager;
		$this->itemMapper = $itemMapper;
		$this->logger = $logger;
		$this->file = $file;
	}

	/**
	 * Is this file good for scanning? 
	 * @return boolean
	 */
	public function isValid() {
		return $this->file->getSize() > 0;
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
			return fread($this->fileHandle, $this->config->getAvChunkSize());
		}
		return false;
	}

	/**
	 * Action to take if this item is infected
	 */
	public function processInfected(Status $status) {
		$infectedAction = $this->config->getAvInfectedAction();
		
		$shouldDelete = $infectedAction === 'delete';
		
		$message = $shouldDelete ? Provider::MESSAGE_FILE_DELETED : '';

		$activity = $this->activityManager->generateEvent();
		$activity->setApp(Application::APP_NAME)
			->setSubject(Provider::SUBJECT_VIRUS_DETECTED, [$this->file->getPath(), $status->getDetails()])
			->setMessage($message)
			->setObject('file', $this->file->getId(), $this->file->getPath())
			->setAffectedUser($this->file->getOwner()->getUID())
			->setType(Provider::TYPE_VIRUS_DETECTED);
		$this->activityManager->publish($activity);

		if ($shouldDelete) {
			$this->logError('Infected file deleted. ' . $status->getDetails());
			$this->deleteFile();
		} else {
			$this->logError('File is infected. '  . $status->getDetails());
		}
	}

	/**
	 * Action to take if this item status is unclear
	 * @param Status $status
	 */
	public function processUnchecked(Status $status) {
		//TODO: Show warning to the user: The file can not be checked
		$this->logError('Not Checked. ' . $status->getDetails());
	}

	/**
	 * Action to take if this item status is not infected
	 */
	public function processClean() {
		try {
			try {
				$item = $this->itemMapper->findByFileId($this->file->getId());
				$this->itemMapper->delete($item);
			} catch (DoesNotExistException $e) {
				//Just ignore
			}

			$item = new \OCA\Files_Antivirus\Db\Item();
			$item->setFileid($this->file->getId());
			$item->setCheckTime(time());
			$this->itemMapper->insert($item);
		} catch(\Exception $e) {
			$this->logger->error(__METHOD__.', exception: '.$e->getMessage(), ['app' => 'files_antivirus']);
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
		$fileHandle = $this->file->fopen('r');
		if ($fileHandle === false) {
			$this->logError('Can not open for reading.');
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
		$this->file->delete();
		if (App::isEnabled('files_trashbin')) {
			\OCA\Files_Trashbin\Storage::postRenameHook([]);
		}
	}

	/**
	 * @param string $message
	 */
	public function logDebug($message) {
		$extra = ' File: ' . $this->file->getId()
				. 'Account: ' . $this->file->getOwner()->getUID()
				. ' Path: ' . $this->file->getPath();
		$this->logger->debug($message . $extra, ['app' => 'files_antivirus']);
	}

	/**
	 * @param string $message
	 */
	public function logError($message) {
		$ownerInfo = 'Account: ' . $this->file->getOwner()->getUID();
		$extra = ' File: ' . $this->file->getId()
				. $ownerInfo 
				. ' Path: ' . $this->file->getPath();
		$this->logger->error($message . $extra, ['app' => 'files_antivirus']);
	}
}
