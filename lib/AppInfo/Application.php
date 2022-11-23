<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\AppInfo;

use OC\Files\Filesystem;
use OC\Files\Storage\Wrapper\Jail;
use OCA\Files_Antivirus\AvirWrapper;
use OCA\Files_Antivirus\Scanner\ScannerFactory;
use OCP\Activity\IManager;
use OCP\App\IAppManager;
use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;
use OCP\Files\IHomeStorage;
use OCP\Files\Storage\IStorage;
use OCP\IL10N;
use OCP\Util;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

class Application extends App implements IBootstrap {
	public const APP_NAME = 'files_antivirus';

	public function __construct(array $urlParams = []) {
		parent::__construct(self::APP_NAME, $urlParams);
	}

	public function register(IRegistrationContext $context): void {
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
				$eventDispatcher = $container->get(EventDispatcherInterface::class);
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
				]);
			},
			1
		);
	}
}
