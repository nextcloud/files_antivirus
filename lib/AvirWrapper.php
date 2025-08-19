<?php

/**
 * SPDX-FileCopyrightText: 2017-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2015-2016 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
namespace OCA\Files_Antivirus;

use OC\Files\Storage\Wrapper\Wrapper;
use OCA\Files_Antivirus\Activity\Provider;
use OCA\Files_Antivirus\AppInfo\Application;
use OCA\Files_Antivirus\Event\ScanStateEvent;
use OCA\Files_Antivirus\Scanner\ScannerFactory;
use OCA\Files_Trashbin\Trash\ITrashManager;
use OCP\Activity\IManager as ActivityManager;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Files\InvalidContentException;
use OCP\IL10N;
use OCP\IUserManager;
use Psr\Log\LoggerInterface;

class AvirWrapper extends Wrapper {
	/**
	 * Modes that are used for writing
	 */
	private array $writingModes = ['r+', 'w', 'w+', 'a', 'a+', 'x', 'x+', 'c', 'c+'];
	protected ScannerFactory$scannerFactory;
	protected IL10N $l10n;
	protected LoggerInterface$logger;
	protected ActivityManager $activityManager;
	protected bool $isHomeStorage;
	private bool $shouldScan = true;
	private bool $trashEnabled;
	private ?string $mountPoint;
	private bool $blockUnscannable = false;
	private IUserManager $userManager;
	private string $blockUnReachable = 'yes';
	private int $chunkSize;

	/**
	 * @param array $parameters
	 */
	public function __construct($parameters) {
		parent::__construct($parameters);
		$this->scannerFactory = $parameters['scannerFactory'];
		$this->l10n = $parameters['l10n'];
		$this->logger = $parameters['logger'];
		$this->activityManager = $parameters['activityManager'];
		$this->isHomeStorage = $parameters['isHomeStorage'];
		$this->trashEnabled = $parameters['trashEnabled'];
		$this->mountPoint = $parameters['mount_point'];
		$this->blockUnscannable = $parameters['block_unscannable'];
		$this->userManager = $parameters['userManager'];
		$this->blockUnReachable = $parameters['block_unreachable'];
		$this->chunkSize = $parameters['chunk_size'];

		/** @var IEventDispatcher $eventDispatcher */
		$eventDispatcher = $parameters['eventDispatcher'];
		$eventDispatcher->addListener(ScanStateEvent::class, function (ScanStateEvent $event) {
			$this->shouldScan = $event->getState();
		});
	}

	/**
	 * Asynchronously scan data that are written to the file
	 * @return resource | false
	 */
	public function fopen(string $path, string $mode) {
		$stream = $this->storage->fopen($path, $mode);

		/*
		 * Only check when
		 *  - it is a resource
		 *  - it is a writing mode
		 *  - if it is a homestorage it starts with files/
		 *  - if it is not a homestorage we always wrap (external storages)
		 */
		if ($this->shouldWrap($path) && is_resource($stream) && $this->isWritingMode($mode)) {
			$stream = $this->wrapSteam($path, $stream);
		}
		return $stream;
	}

	public function writeStream(string $path, $stream, ?int $size = null): int {
		if ($this->shouldWrap($path)) {
			$stream = $this->wrapSteam($path, $stream);
		}
		return parent::writeStream($path, $stream, $size);
	}

	private function shouldWrap(string $path): bool {
		return $this->shouldScan
			&& (!$this->isHomeStorage
				|| (strpos($path, 'files/') === 0
					|| strpos($path, '/files/') === 0)
			)
			&& !$this->isPartFile($path);
	}

	private function isPartFile(string $path): bool {
		return preg_match('/\.ocTransferId\d+\.part$/i', $path);
	}

	public function rename(string $source, string $target): bool {
		if (!$this->isPartFile($source) || !$this->shouldWrap($target)) {
			return parent::rename($source, $target);
		}

		$scanner = $this->scannerFactory->getScanner($this->mountPoint . $target);
		$scanner->initScanner();

		$stream = $this->fopen($source, 'rb');
		while ($data = fread($stream, $this->chunkSize)) {
			$scanner->onAsyncData($data);
		}
		fclose($stream);

		$status = $scanner->completeAsyncScan();
		if ($status->getNumericStatus() === Status::SCANRESULT_INFECTED) {
			$this->handleInfected($source, $status);
		}
		if ($this->blockUnscannable && $status->getNumericStatus() === Status::SCANRESULT_UNSCANNABLE) {
			$this->handleInfected($source, $status);
		}

		return parent::rename($source, $target);
	}

	private function wrapSteam(string $path, $stream) {
		if ($this->isPartFile($path)) {
			return $stream;
		}

		try {
			$scanner = $this->scannerFactory->getScanner($this->mountPoint ? $this->mountPoint . $path : null);
			$scanner->initScanner();
			return CallbackReadDataWrapper::wrap(
				$stream,
				function ($count, $data) use ($scanner) {
					$scanner->onAsyncData($data);
				},
				function ($data) use ($scanner) {
					$scanner->onAsyncData($data);
				},
				function () use ($scanner, $path) {
					$status = $scanner->completeAsyncScan();
					if ($status->getNumericStatus() === Status::SCANRESULT_INFECTED) {
						$this->handleInfected($path, $status);
					}
					if ($this->blockUnscannable && $status->getNumericStatus() === Status::SCANRESULT_UNSCANNABLE) {
						$this->handleInfected($path, $status);
					}
				}
			);
		} catch (\Exception $e) {
			$this->logger->error($e->getMessage(), ['exception' => $e]);
			if($this->blockUnReachable == 'yes') {
				$this->handleConnectionError($path);
			}
		}
		return $stream;
	}

	/**
	 * Checks whether passed mode is suitable for writing
	 * @param string $mode
	 * @return bool
	 */
	private function isWritingMode($mode) {
		// Strip unessential binary/text flags
		$cleanMode = str_replace(
			['t', 'b'],
			['', ''],
			$mode
		);
		return in_array($cleanMode, $this->writingModes);
	}

	/**
	 * Synchronously scan data that is written to a file by the bulk upload endpoint
	 *
	 * @return false|float|int
	 * @throws InvalidContentException
	 */
	public function file_put_contents(string $path, mixed $data): int|float|false {
		if ($this->shouldWrap($path)) {
			$scanner = $this->scannerFactory->getScanner($this->mountPoint . $path);
			$scanner->initScanner();
			$status = $scanner->scanString($data);
			if ($status->getNumericStatus() === Status::SCANRESULT_INFECTED) {
				$this->handleInfected($path, $status);
			}
		}

		return parent::file_put_contents($path, $data);
	}

	/**
	 * @throws InvalidContentException
	 */
	private function handleInfected(string $path, Status $status): void {
		//prevent from going to trashbin
		if ($this->trashEnabled) {
			/** @var ITrashManager $trashManager */
			$trashManager = \OC::$server->query(ITrashManager::class);
			$trashManager->pauseTrash();
		}

		$owner = $this->getOwner($path);
		$user = $this->userManager->get($owner);
		$this->unlink($path);

		if ($this->trashEnabled) {
			/** @var ITrashManager $trashManager */
			$trashManager = \OC::$server->query(ITrashManager::class);
			$trashManager->resumeTrash();
		}

		$this->logger->warning(
			'Infected file deleted. ' . $status->getDetails() . ' Account: ' . $owner . ' Path: ' . $path, [
				'app' => 'files_antivirus',
				'userId' => $user?->getUID(),
				'userName' => $user?->getDisplayName(),
				'file' => $path,
			]);


		$activity = $this->activityManager->generateEvent();
		$activity->setApp(Application::APP_NAME)
			->setSubject(Provider::SUBJECT_VIRUS_DETECTED_UPLOAD, [$status->getDetails()])
			->setMessage(Provider::MESSAGE_FILE_DELETED)
			->setObject('', 0, $path)
			->setAffectedUser($owner)
			->setType(Provider::TYPE_VIRUS_DETECTED);
		$this->activityManager->publish($activity);

		$this->logger->error('Infected file deleted. ' . $status->getDetails() . ' File: ' . $path . ' Account: ' . $owner, [
			'app' => 'files_antivirus',
			'userId' => $user?->getUID(),
			'userName' => $user?->getDisplayName(),
			'file' => $path,
		]);

		throw new InvalidContentException(
			$this->l10n->t(
				'Virus %s is detected in the file. Upload cannot be completed.',
				$status->getDetails()
			)
		);
	}

	/**
	 * @throws InvalidContentException
	 */
	protected function handleConnectionError(string $path): void {
		//prevent from going to trashbin
		if ($this->trashEnabled) {
			/** @var ITrashManager $trashManager */
			$trashManager = \OC::$server->query(ITrashManager::class);
			$trashManager->pauseTrash();
		}

		$this->unlink($path);

		if ($this->trashEnabled) {
			/** @var ITrashManager $trashManager */
			$trashManager = \OC::$server->query(ITrashManager::class);
			$trashManager->resumeTrash();
		}

		throw new InvalidContentException(
			$this->l10n->t(
				'%s. Upload cannot be completed.',
				['No connection to anti virus']
			)
		);
	}

}
