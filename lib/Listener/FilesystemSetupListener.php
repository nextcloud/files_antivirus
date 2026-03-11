<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Listener;

use OC\Files\Filesystem;
use OC\Files\Storage\Wrapper\Jail;
use OCA\Files_Antivirus\AppConfig;
use OCA\Files_Antivirus\AppInfo\Application;
use OCA\Files_Antivirus\AvirWrapper;
use OCA\Files_Antivirus\Scanner\ScannerFactory;
use OCA\GroupFolders\Mount\GroupFolderEncryptionJail;
use OCP\Activity\IManager as IActivityManager;
use OCP\App\IAppManager;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\EventDispatcher\IEventListener;
use OCP\Files\Events\BeforeFileSystemSetupEvent;
use OCP\Files\IHomeStorage;
use OCP\Files\Storage\ISharedStorage;
use OCP\Files\Storage\IStorage;
use OCP\IAppConfig;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUserManager;
use OCP\L10N\IFactory as IL10NFactory;
use Psr\Log\LoggerInterface;

/** @template-implements IEventListener<BeforeFileSystemSetupEvent> */
class FilesystemSetupListener implements IEventListener {
	private bool $groupFolderEncryptionEnabled;
	private IL10N $l10n;

	public function __construct(
		private readonly ScannerFactory $scannerFactory,
		private readonly LoggerInterface $logger,
		private readonly IAppManager $appManager,
		private readonly AppConfig $avAppConfig,
		private readonly IRequest $request,
		private readonly IUserManager $userManager,
		private readonly IEventDispatcher $eventDispatcher,
		private readonly IActivityManager $activityManager,
		IL10NFactory $l10nFactory,
		IAppConfig $appConfig,
	) {
		$this->l10n = $l10nFactory->get(Application::APP_NAME);
		$this->groupFolderEncryptionEnabled = $appConfig->getValueBool('groupfolders', 'enable_encryption');
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof BeforeFileSystemSetupEvent) {
			return;
		}

		Filesystem::addStorageWrapper(
			'oc_avir',
			function (string $mountPoint, IStorage $storage) {
				if (
					$storage->instanceOfStorage(AvirWrapper::class)
					&& $storage->instanceOfStorage(Jail::class) && (
						$storage->instanceOfStorage(ISharedStorage::class)
						|| !(
							$this->groupFolderEncryptionEnabled
							&& $storage->instanceOfStorage(GroupFolderEncryptionJail::class)
						)
					)
				) {
					// No reason to wrap jails again.
					// Make an exception for encrypted group folders.
					return $storage;
				}

				return new AvirWrapper([
					'storage' => $storage,
					'scannerFactory' => $this->scannerFactory,
					'l10n' => $this->l10n,
					'logger' => $this->logger,
					'activityManager' => $this->activityManager,
					'isHomeStorage' => $storage->instanceOfStorage(IHomeStorage::class),
					'eventDispatcher' => $this->eventDispatcher,
					'trashEnabled' => $this->appManager->isEnabledForUser('files_trashbin'),
					'mount_point' => $mountPoint,
					'block_unscannable' => $this->avAppConfig->getAvBlockUnscannable(),
					'userManager' => $this->userManager,
					'block_unreachable' => $this->avAppConfig->getAvBlockUnreachable() === 'yes',
					'request' => $this->request,
					'groupFoldersEnabled' => $this->appManager->isEnabledForUser('groupfolders'),
					'e2eeEnabled' => $this->appManager->isEnabledForUser('end_to_end_encryption'),
					'blockListedDirectories' => $this->avAppConfig->getAvBlocklistedDirectories(),
				]);
			},
			1,
		);
	}


}
