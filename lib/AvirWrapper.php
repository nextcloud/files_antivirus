<?php
/**
 * Copyright (c) 2014 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus;

use OC\Files\Storage\Wrapper\Wrapper;
use OCA\Files_Antivirus\Activity\Provider;
use OCA\Files_Antivirus\AppInfo\Application;
use OCA\Files_Antivirus\Event\ScanStateEvent;
use OCA\Files_Antivirus\Scanner\ScannerFactory;
use OCA\Files_Trashbin\Trash\ITrashManager;
use OCP\Activity\IManager as ActivityManager;
use OCP\Files\InvalidContentException;
use OCP\IL10N;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

class AvirWrapper extends Wrapper {
	/**
	 * Modes that are used for writing
	 * @var array
	 */
	private $writingModes = ['r+', 'w', 'w+', 'a', 'a+', 'x', 'x+', 'c', 'c+'];

	/** @var ScannerFactory */
	protected $scannerFactory;

	/** @var IL10N */
	protected $l10n;

	/** @var LoggerInterface */
	protected $logger;

	/** @var ActivityManager */
	protected $activityManager;

	/** @var bool */
	protected $isHomeStorage;

	/** @var bool */
	private $shouldScan = true;

	/** @var bool */
	private $trashEnabled;

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

		/** @var EventDispatcherInterface $eventDispatcher */
		$eventDispatcher = $parameters['eventDispatcher'];
		$eventDispatcher->addListener(ScanStateEvent::class, function (ScanStateEvent $event) {
			$this->shouldScan = $event->getState();
		});
	}

	/**
	 * Asynchronously scan data that are written to the file
	 * @param string $path
	 * @param string $mode
	 * @return resource | false
	 */
	public function fopen($path, $mode) {
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

	public function writeStream(string $path, $stream, int $size = null): int {
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
			);
	}

	private function wrapSteam(string $path, $stream) {
		try {
			$scanner = $this->scannerFactory->getScanner();
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
						//prevent from going to trashbin
						if ($this->trashEnabled) {
							/** @var ITrashManager $trashManager */
							$trashManager = \OC::$server->query(ITrashManager::class);
							$trashManager->pauseTrash();
						}

						$owner = $this->getOwner($path);
						$this->unlink($path);

						if ($this->trashEnabled) {
							/** @var ITrashManager $trashManager */
							$trashManager = \OC::$server->query(ITrashManager::class);
							$trashManager->resumeTrash();
						}

						$this->logger->warning(
							'Infected file deleted. ' . $status->getDetails()
							. ' Account: ' . $owner . ' Path: ' . $path,
							['app' => 'files_antivirus']
						);

						$activity = $this->activityManager->generateEvent();
						$activity->setApp(Application::APP_NAME)
							->setSubject(Provider::SUBJECT_VIRUS_DETECTED_UPLOAD, [$status->getDetails()])
							->setMessage(Provider::MESSAGE_FILE_DELETED)
							->setObject('', 0, $path)
							->setAffectedUser($owner)
							->setType(Provider::TYPE_VIRUS_DETECTED);
						$this->activityManager->publish($activity);

						$this->logger->error('Infected file deleted. ' . $status->getDetails() .
							' File: ' . $path . ' Account: ' . $owner, ['app' => 'files_antivirus']);

						throw new InvalidContentException(
							$this->l10n->t(
								'Virus %s is detected in the file. Upload cannot be completed.',
								$status->getDetails()
							)
						);
					}
				}
			);
		} catch (\Exception $e) {
			$this->logger->error($e->getMessage(), ['exception' => $e]);
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
}
