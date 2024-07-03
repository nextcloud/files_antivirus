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
use OCP\Activity\IManager;
use OCP\App\IAppManager;
use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Files\IHomeStorage;
use OCP\Files\Storage\IStorage;
use OCP\Http\Client\IClientService;
use OCP\ICertificateManager;
use OCP\IL10N;
use OCP\Util;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

class Application extends App implements IBootstrap {
	public const APP_NAME = 'files_antivirus';

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
	}

	/**
	 * 	 * Add wrapper for local storages
	 */
	public function setupWrapper(): void {
		Filesystem::addStorageWrapper(
			'oc_avir',
			function (string $mountPoint, IStorage $storage) {
				if ($storage->instanceOfStorage(Jail::class)) {
					// No reason to wrap jails again
					return $storage;
				}

				$container = $this->getContainer();
				$scannerFactory = $container->query(ScannerFactory::class);
				$l10n = $container->get(IL10N::class);
				$logger = $container->get(LoggerInterface::class);
				$activityManager = $container->get(IManager::class);
				$eventDispatcher = $container->get(IEventDispatcher::class);
				$appManager = $container->get(IAppManager::class);
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
				]);
			},
			1
		);
	}
}
