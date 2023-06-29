<?php

declare(strict_types=1);

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
use OCA\Files_Trashbin\Trash\ITrashManager;
use OCP\Activity\IManager as ActivityManager;
use OCP\App\IAppManager;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Files\File;
use OCP\Files\IRootFolder;
use Psr\Log\LoggerInterface;

class Item {
	/**
	 * file handle, user to read from the file
	 *
	 * @var resource
	 */
	protected $fileHandle;

	private AppConfig $config;
	private ActivityManager $activityManager;
	private ItemMapper $itemMapper;
	private LoggerInterface $logger;
	private IRootFolder $rootFolder;
	private IAppManager $appManager;
	private File $file;
	private bool $isCron;
	private ITimeFactory $clock;

	/**
	 * Item constructor.
	 */
	public function __construct(
		AppConfig $appConfig,
		ActivityManager $activityManager,
		ItemMapper $itemMapper,
		LoggerInterface $logger,
		IRootFolder $rootFolder,
		IAppManager $appManager,
		File $file,
		ITimeFactory $clock,
		bool $isCron
	) {
		$this->config = $appConfig;
		$this->activityManager = $activityManager;
		$this->itemMapper = $itemMapper;
		$this->appManager = $appManager;
		$this->logger = $logger;
		$this->rootFolder = $rootFolder;
		$this->file = $file;
		$this->clock = $clock;
		$this->isCron = $isCron;
	}

	/**
	 * Reads a file portion by portion until the very end
	 *
	 * @return string|false
	 */
	public function fread() {
		if (!($this->file->getSize() > 0)) {
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
	 * 	 * Action to take if this item is infected
	 */
	public function processInfected(Status $status): void {
		$infectedAction = $this->config->getAvInfectedAction();

		$shouldDelete = $infectedAction === 'delete';

		$message = $shouldDelete ? Provider::MESSAGE_FILE_DELETED : '';

		$userFolder = $this->rootFolder->getUserFolder($this->file->getOwner()->getUID());
		$path = $userFolder->getRelativePath($this->file->getPath());

		$activity = $this->activityManager->generateEvent();
		$activity->setApp(Application::APP_NAME)
			->setSubject(Provider::SUBJECT_VIRUS_DETECTED_SCAN, [$status->getDetails()])
			->setMessage($message)
			->setObject('file', $this->file->getId(), $path)
			->setAffectedUser($this->file->getOwner()->getUID())
			->setType(Provider::TYPE_VIRUS_DETECTED);
		$this->activityManager->publish($activity);

		if ($shouldDelete) {
			if ($this->isCron) {
				$msg = 'Infected file deleted (during background scan)';
			} else {
				$msg = 'Infected file deleted.';
			}
			$this->logError($msg . ' ' . $status->getDetails());
			$this->deleteFile();
		} else {
			if ($this->isCron) {
				$msg = 'Infected file found (during background scan)';
			} else {
				$msg = 'Infected file found.';
			}
			$this->logError($msg . ' ' . $status->getDetails());
			$this->updateCheckTime($this->clock->getTime());
		}
	}

	/**
	 * 	 * Action to take if this item status is unclear
	 * 	 *
	 *
	 * @param Status $status
	 */
	public function processUnchecked(Status $status): void {
		//TODO: Show warning to the user: The file can not be checked
		$this->logError('Not Checked. ' . $status->getDetails());
	}

	/**
	 * 	 * Action to take if this item status is not infected
	 */
	public function processClean(): void {
		$this->updateCheckTime($this->clock->getTime());
	}

	/**
	 * 	 * Update the check-time of this item to provider time
	 */
	public function updateCheckTime(int $time): void {
		try {
			$this->removeCheckTime();

			$item = new Db\Item();
			$item->setFileid($this->file->getId());
			$item->setCheckTime($time);
			$this->itemMapper->insert($item);
		} catch (\Exception $e) {
			$this->logger->error(__METHOD__ . ', exception: ' . $e->getMessage(), ['app' => 'files_antivirus']);
		}
	}

	/**
	 * remove the checked time for the item, effectively marking it as unscanned
	 */
	public function removeCheckTime(): void {
		try {
			$item = $this->itemMapper->findByFileId($this->file->getId());
			$this->itemMapper->delete($item);
		} catch (DoesNotExistException $e) {
			//Just ignore
		}
	}

	/**
	 * Check if the end of file is reached
	 */
	private function feof(): bool {
		$isDone = feof($this->fileHandle);
		if ($isDone) {
			$this->logDebug('Scan is done');
			$handle = $this->fileHandle;
			fclose($handle);
			$this->fileHandle = null;
		}
		return $isDone;
	}

	/**
	 * 	 * Opens a file for reading
	 * 	 *
	 *
	 * @throws \RuntimeException
	 */
	private function getFileHandle(): void {
		$fileHandle = $this->file->fopen('r');
		if ($fileHandle === false) {
			$this->logError('Can not open for reading.');
			throw new \RuntimeException();
		}

		$this->logDebug('Scan started');
		$this->fileHandle = $fileHandle;
	}

	/**
	 * 	 * Delete infected file
	 */
	private function deleteFile(): void {
		//prevent from going to trashbin
		if ($this->appManager->isEnabledForUser('files_trashbin')) {
			/** @var ITrashManager $trashManager */
			$trashManager = \OC::$server->get(ITrashManager::class);
			$trashManager->pauseTrash();
		}
		$this->file->delete();
		if ($this->appManager->isEnabledForUser('files_trashbin')) {
			/** @var ITrashManager $trashManager */
			$trashManager = \OC::$server->get(ITrashManager::class);
			$trashManager->resumeTrash();
		}
	}

	private function generateExtraInfo(): string {
		$owner = $this->file->getOwner();

		if ($owner === null) {
			$ownerInfo = ' Account: NO OWNER FOUND';
		} else {
			$ownerInfo = ' Account: ' . $owner->getUID();
		}

		$extra = ' File: ' . $this->file->getId()
			. $ownerInfo
			. ' Path: ' . $this->file->getPath();

		return $extra;
	}

	/**
	 * @param string $message
	 */
	public function logDebug($message): void {
		$this->logger->debug($message . $this->generateExtraInfo(), ['app' => 'files_antivirus']);
	}

	/**
	 * @param string $message
	 */
	public function logError($message): void {
		$this->logger->error($message . $this->generateExtraInfo(), ['app' => 'files_antivirus']);
	}
}
