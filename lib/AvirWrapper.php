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
use OCA\GroupFolders\Folder\FolderManager;
use OCP\Activity\IManager;
use OCP\Activity\IManager as ActivityManager;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Files\InvalidContentException;
use OCP\Files\IRootFolder;
use OCP\Files\Storage\IStorage;
use OCP\IConfig;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUserManager;
use OCP\Server;
use Psr\Log\LoggerInterface;

class AvirWrapper extends Wrapper {
	/**
	 * Modes that are used for writing
	 */
	private array $writingModes = ['r+', 'w', 'w+', 'a', 'a+', 'x', 'x+', 'c', 'c+'];
	protected ScannerFactory $scannerFactory;
	protected IL10N $l10n;
	protected LoggerInterface $logger;
	protected ActivityManager $activityManager;
	protected bool $isHomeStorage;
	private bool $shouldScan = true;
	private bool $trashEnabled;
	private bool $groupFoldersEnabled;
	private bool $e2eeEnabled;
	private ?string $mountPoint;
	private bool $blockUnscannable;
	private IUserManager $userManager;
	private bool $blockUnReachable;
	private IRequest $request;
	private array $blockListedDirectories;
	private ScannedPathsRegistry $scannedPathsRegistry;

	/**
	 * @psalm-suppress MoreSpecificImplementedParamType
	 * @param array{
	 *     storage: IStorage,
	 *     scannerFactory: ScannerFactory,
	 *     l10n: IL10N,
	 *     logger: LoggerInterface,
	 *     activityManager: IManager,
	 *     isHomeStorage: bool,
	 *     eventDispatcher: IEventDispatcher,
	 *     trashEnabled: bool,
	 *     mount_point: string,
	 *     block_unscannable: bool,
	 *     userManager: IUserManager,
	 *     block_unreachable: bool,
	 *     request: IRequest,
	 *     groupFoldersEnabled: bool,
	 *     e2eeEnabled: bool,
	 *     blockListedDirectories: array,
	 *     scannedPathsRegistry: ScannedPathsRegistry,
	 * } $parameters
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
		$this->request = $parameters['request'];
		$this->groupFoldersEnabled = $parameters['groupFoldersEnabled'];
		$this->e2eeEnabled = $parameters['e2eeEnabled'];
		$this->blockListedDirectories = $parameters['blockListedDirectories'];
		$this->scannedPathsRegistry = $parameters['scannedPathsRegistry'];

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

	public function shouldWrap(string $path): bool {
		if ($this->blockListedDirectories) {
			$relativePathParts = explode('/', $this->mountPoint . $path);
			if (array_intersect($relativePathParts, $this->blockListedDirectories)) {
				// Don't scan directory or new group folders in the block list
				return false;
			}
			if ($this->groupFoldersEnabled) {
				/** @var FolderManager $folderManager */
				$folderManager = \OCP\Server::get(FolderManager::class);

				if (preg_match('#^/?__groupfolders/(\d+)#', $path, $matches)) {
					$folderId = (int)$matches[1];
					$folder = $folderManager->getFolder($folderId);

					if ($folderId === $folder->id
						&& in_array($folder->mountPoint, $this->blockListedDirectories)) {
						// Don't scan old group folders in the block list
						return false;
					}
				}
			}
		}

		if ($this->e2eeEnabled) {
			// Don't scan E2EE metadata files.
			$config = \OCP\Server::get(IConfig::class);
			$instanceId = $config->getSystemValue('instanceid', null);
			if (str_starts_with($path, "appdata_$instanceId/end_to_end_encryption/")) {
				return false;
			}
			// Don't scan E2EE files.
			$parentId = $this->storage->getCache()->getParentId($path);
			$rootFolder = \OCP\Server::get(IRootFolder::class);
			$owner = $this->storage->getOwner($path);
			if ($owner !== false) {
				$userFolder = $rootFolder->getUserFolder($owner);
				$node = $userFolder->getFirstNodeById($parentId);
				if ($node !== null && $node->isEncrypted()) {
					return false;
				}
			}
		}

		return $this->shouldScan
			&& (!$this->isHomeStorage
				|| (strpos($path, 'files/') === 0
					|| strpos($path, '/files/') === 0)
			);
	}

	/**
	 * Build the registry key for a path: the absolute path the committed file will have,
	 * matching Node::getPath() used in NodeWrittenListener.
	 *
	 * For hashed .part files (e.g. abc123.ocTransferId1234.part) the real filename is
	 * not recoverable from the storage path — we must read it from the DAV request URI,
	 * the same technique used by getPathForScanner(). The DAV URI has the form
	 * /dav/files/{username}/{relative_path}, which maps to /{username}/files/{relative_path}
	 * in Node::getPath().
	 */
	private function getRegistryPath(string $path): string {
		if (preg_match('/\.ocTransferId\d+\.part$/i', $path)) {
			$davFilesPrefix = '/dav/files';
			$pathInfo = $this->request->getPathInfo();
			if (str_starts_with($pathInfo, $davFilesPrefix)) {
				$afterPrefix = substr($pathInfo, strlen($davFilesPrefix)); // /{username}/{relative}
				$secondSlash = strpos($afterPrefix, '/', 1);
				if ($secondSlash !== false) {
					// Insert /files between the username segment and the rest of the path
					return substr($afterPrefix, 0, $secondSlash) . '/files' . substr($afterPrefix, $secondSlash);
				}
			}
		}

		// Non-hashed paths (file_put_contents, writeStream, or non-DAV uploads):
		// mount point + storage-relative path is already the correct absolute path.
		$normalizedPath = preg_replace('/\.ocTransferId\d+\.part$/i', '', $path) ?? $path;
		return rtrim($this->mountPoint ?? '', '/') . '/' . ltrim($normalizedPath, '/');
	}

	/**
	 * Try to extract actual path for .ocTransferId.part files (because the name is hashed).
	 */
	private function getPathForScanner(string $path): ?string {
		$defaultReturnValue = null;
		if ($this->mountPoint !== null) {
			$defaultReturnValue = $this->mountPoint . $path;
		}

		if (!preg_match('/\.ocTransferId\d+\.part$/i', $path)) {
			return $defaultReturnValue;
		}

		$davFilesPrefix = '/dav/files';
		if (!str_starts_with($this->request->getPathInfo(), $davFilesPrefix)) {
			return $defaultReturnValue;
		}

		return substr($this->request->getPathInfo(), strlen($davFilesPrefix));
	}

	public function wrapSteam(string $path, $stream) {
		try {
			$scanner = $this->scannerFactory->getScanner($this->getPathForScanner($path));
			$scanner->initScanner();
			$amountRead = 0;
			return CallbackReadDataWrapper::wrap(
				$stream,
				function ($count, $data) use ($scanner, $stream, &$amountRead) {
					$pos = ftell($stream);
					// don't scan twice when the stream is seeked backwards during reading
					if ($pos > $amountRead) {
						$scanner->onAsyncData($data);
						$amountRead = $pos;
					}
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
					if ($this->blockUnReachable && $status->getNumericStatus() === Status::SCANRESULT_UNCHECKED) {
						$this->handleConnectionError($path);
					}
					// Register result only when the file is accepted (not blocked).
					// UNCHECKED without block_unreachable means AV was unreachable — do NOT
					// mark as scanned so the background scanner retries it.
					if (
						$status->getNumericStatus() === Status::SCANRESULT_CLEAN
						|| ($status->getNumericStatus() === Status::SCANRESULT_UNSCANNABLE && !$this->blockUnscannable)
					) {
						$registryPath = $this->getRegistryPath($path);
						$this->scannedPathsRegistry->registerResult($registryPath, $status->getNumericStatus());
					}
				}
			);
		} catch (\Exception $e) {
			$this->logger->error($e->getMessage(), ['exception' => $e]);
			if ($this->blockUnReachable) {
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
			$scanner = $this->scannerFactory->getScanner($this->getPathForScanner($path));
			$scanner->initScanner();
			$status = $scanner->scanString($data);
			if ($status->getNumericStatus() === Status::SCANRESULT_INFECTED) {
				$this->handleInfected($path, $status);
			}
			if ($this->blockUnscannable && $status->getNumericStatus() === Status::SCANRESULT_UNSCANNABLE) {
				$this->handleInfected($path, $status);
			}
			if ($this->blockUnReachable && $status->getNumericStatus() === Status::SCANRESULT_UNCHECKED) {
				$this->handleConnectionError($path);
			}
			// Register result only when the file is accepted (not blocked).
			if (
				$status->getNumericStatus() === Status::SCANRESULT_CLEAN
				|| ($status->getNumericStatus() === Status::SCANRESULT_UNSCANNABLE && !$this->blockUnscannable)
			) {
				$this->scannedPathsRegistry->registerResult($this->getRegistryPath($path), $status->getNumericStatus());
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
			$trashManager = Server::get(ITrashManager::class);
			$trashManager->pauseTrash();
		}

		$owner = $this->getOwner($path);
		$user = $this->userManager->get($owner);
		$this->unlink($path);

		if ($this->trashEnabled) {
			$trashManager = Server::get(ITrashManager::class);
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
			$trashManager = Server::get(ITrashManager::class);
			$trashManager->pauseTrash();
		}

		$this->unlink($path);

		if ($this->trashEnabled) {
			$trashManager = Server::get(ITrashManager::class);
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
