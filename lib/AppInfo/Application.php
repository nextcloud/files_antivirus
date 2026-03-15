<?php

/**
 * SPDX-FileCopyrightText: 2017-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2015-2016 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\AppInfo;

use OCA\Files_Antivirus\AppConfig;
use OCA\Files_Antivirus\Listener\FilesystemSetupListener;
use OCA\Files_Antivirus\Scanner\ExternalClam;
use OCA\Files_Antivirus\Scanner\ExternalKaspersky;
use OCA\Files_Antivirus\Scanner\ICAP;
use OCA\Files_Antivirus\Scanner\LocalClam;
use OCA\Files_Antivirus\StatusFactory;
use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;
use OCP\Files\Events\BeforeFileSystemSetupEvent;
use OCP\Http\Client\IClientService;
use OCP\ICertificateManager;
use OCP\IConfig;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

class Application extends App implements IBootstrap {
	public const APP_NAME = 'files_antivirus';

	public function __construct(array $urlParams = []) {
		parent::__construct(self::APP_NAME, $urlParams);
	}

	#[\Override]
	public function register(IRegistrationContext $context): void {
		$context->registerService(ExternalClam::class, function (ContainerInterface $c) {
			return new ExternalClam(
				$c->get(IConfig::class),
				$c->get(AppConfig::class),
				$c->get(LoggerInterface::class),
				$c->get(StatusFactory::class),
			);
		}, false);

		$context->registerService(LocalClam::class, function (ContainerInterface $c) {
			return new LocalClam(
				$c->get(IConfig::class),
				$c->get(AppConfig::class),
				$c->get(LoggerInterface::class),
				$c->get(StatusFactory::class),
			);
		}, false);

		$context->registerService(ExternalKaspersky::class, function (ContainerInterface $c) {
			return new ExternalKaspersky(
				$c->get(IConfig::class),
				$c->get(AppConfig::class),
				$c->get(LoggerInterface::class),
				$c->get(StatusFactory::class),
				$c->get(IClientService::class),
			);
		}, false);

		$context->registerService(ICAP::class, function (ContainerInterface $c) {
			return new ICAP(
				$c->get(IConfig::class),
				$c->get(AppConfig::class),
				$c->get(LoggerInterface::class),
				$c->get(StatusFactory::class),
				$c->get(ICertificateManager::class),
			);
		}, false);

		$context->registerEventListener(BeforeFileSystemSetupEvent::class, FilesystemSetupListener::class);
	}

	#[\Override]
	public function boot(IBootContext $context): void {
	}
}
