<?php

/**
 * SPDX-FileCopyrightText: 2017-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2015-2016 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\AppInfo;

use OC\Files\Filesystem;
use OC\Files\Storage\Wrapper\Jail;
use OCA\Files_Antivirus\AppConfig;
use OCA\Files_Antivirus\AvirWrapper;
use OCA\Files_Antivirus\Scanner\ExternalClam;
use OCA\Files_Antivirus\Scanner\ExternalKaspersky;
use OCA\Files_Antivirus\Scanner\ICAP;
use OCA\Files_Antivirus\Scanner\LocalClam;
use OCA\Files_Antivirus\Scanner\ScannerFactory;
use OCA\Files_Antivirus\StatusFactory;
use OCA\GroupFolders\Mount\GroupFolderEncryptionJail;
use OCP\Activity\IManager;
use OCP\App\IAppManager;
use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Files\IHomeStorage;
use OCP\Files\Storage\ISharedStorage;
use OCP\Files\Storage\IStorage;
use OCP\Http\Client\IClientService;
use OCP\IAppConfig;
use OCP\ICertificateManager;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUserManager;
use OCP\Util;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

class Application extends App implements IBootstrap {
	public const APP_NAME = 'files_antivirus';

	private ?bool $groupFolderEncryptionEnabled = null;
	private ?IAppConfig $appConfig = null;

	public function __construct(array $urlParams = []) {
		parent::__construct(self::APP_NAME, $urlParams);
	}

	public function register(IRegistrationContext $context): void {
		$context->registerService(ExternalClam::class, function (ContainerInterface $c) {
			return new ExternalClam(
				$c->get(AppConfig::class),
				$c->get(LoggerInterface::class),
				$c->get(StatusFactory::class),
			);
		}, false);

		$context->registerService(LocalClam::class, function (ContainerInterface $c) {
			return new LocalClam(
				$c->get(AppConfig::class),
				$c->get(LoggerInterface::class),
				$c->get(StatusFactory::class),
			);
		}, false);

		$context->registerService(ExternalKaspersky::class, function (ContainerInterface $c) {
			return new ExternalKaspersky(
				$c->get(AppConfig::class),
				$c->get(LoggerInterface::class),
				$c->get(StatusFactory::class),
				$c->get(IClientService::class),
			);
		}, false);

		$context->registerService(ICAP::class, function (ContainerInterface $c) {
			return new ICAP(
				$c->get(AppConfig::class),
				$c->get(LoggerInterface::class),
				$c->get(StatusFactory::class),
				$c->get(ICertificateManager::class),
			);
		}, false);

		Util::connectHook('OC_Filesystem', 'preSetup', $this, 'setupWrapper');
	}

	public function boot(IBootContext $context): void {
		$this->appConfig = $context->getServerContainer()->get(IAppConfig::class);
	}

	/**
	 * Add wrapper for local storages
	 */
	public function setupWrapper(): void {
		if ($this->groupFolderEncryptionEnabled === null && $this->appConfig) {
			$this->groupFolderEncryptionEnabled = $this->appConfig->getValueBool('groupfolders', 'enable_encryption');
		}

		Filesystem::addStorageWrapper(
			'oc_avir',
			function (string $mountPoint, IStorage $storage) {
				if (
					$storage->instanceOfStorage(AvirWrapper::class) &&
					$storage->instanceOfStorage(Jail::class) && (
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

				$container = $this->getContainer();
				$scannerFactory = $container->query(ScannerFactory::class);
				$l10n = $container->get(IL10N::class);
				$logger = $container->get(LoggerInterface::class);
				$activityManager = $container->get(IManager::class);
				$eventDispatcher = $container->get(IEventDispatcher::class);
				$appManager = $container->get(IAppManager::class);
				/** @var AppConfig $appConfig */
				$appConfig = $container->get(AppConfig::class);
				$userManager = $container->get(IUserManager::class);

				return new AvirWrapper([
					'storage' => $storage,
					'scannerFactory' => $scannerFactory,
					'l10n' => $l10n,
					'logger' => $logger,
					'activityManager' => $activityManager,
					'isHomeStorage' => $storage->instanceOfStorage(IHomeStorage::class),
					'eventDispatcher' => $eventDispatcher,
					'trashEnabled' => $appManager->isEnabledForUser('files_trashbin'),
					'mount_point' => $mountPoint,
					'block_unscannable' => $appConfig->getAvBlockUnscannable(),
					'userManager' => $userManager,
					'block_unreachable' => $appConfig->getAvBlockUnreachable(),
					'request' => $container->get(IRequest::class),
					'groupFoldersEnabled' => $appManager->isEnabledForUser('groupfolders'),
					'e2eeEnabled' => $appManager->isEnabledForUser('end_to_end_encryption'),
					'blockListedDirectories' => $appConfig->getAvBlocklistedDirectories(),
				]);
			},
			1,
		);
	}
}
