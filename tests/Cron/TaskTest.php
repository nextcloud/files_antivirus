<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\Tests\Cron;

use OC\User\Manager;
use \OCA\Files_Antivirus\ScannerFactory;
use \OCA\Files_Antivirus\BackgroundScanner;
use OCA\Files_antivirus\Tests\TestBase;
use OCP\IConfig;
use OCP\ILogger;
use OCP\IUserManager;
use Test\Util\User\Dummy;

/**
 * @group DB
 */
class TaskTest extends TestBase {
	/** @var ScannerFactory */
	private $scannerFactory;

	/** @var IUserManager */
	private $userManager;

	public function setUp(){
		parent::setUp();

		/** @var IConfig $config */
		$config = $this->createMock(IConfig::class);
		$this->userManager = new Manager($config);
		$this->userManager->registerBackend(new Dummy());

		/** @var ILogger $logger */
		$logger = $this->createMock(ILogger::class);

		$this->scannerFactory = new ScannerFactory(
				$this->config,
				$logger
		);
	}
	
	public function testRun(){
		$backgroundScanner = new BackgroundScanner(
				$this->scannerFactory,
				$this->l10n,
				$this->container->query('AppConfig'),
				$this->container->getServer()->getRootFolder(),
				$this->container->getServer()->getUserSession()
		);
		$bgScan = $backgroundScanner->run();
		$this->assertNull($bgScan);
	}
}
