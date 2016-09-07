<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_antivirus\Tests\Cron;

use \OCA\Files_Antivirus\Db\RuleMapper;
use \OCA\Files_Antivirus\Item;
use \OCA\Files_Antivirus\ScannerFactory;
use \OCA\Files_Antivirus\BackgroundScanner;
use OCA\Files_antivirus\Tests\TestBase;

class TaskTest extends TestBase {
	/** @var  ScannerFactory */
	protected $scannerFactory;

	public function setUp(){
		parent::setUp();
		//Background scanner requires at least one user on the current instance
		$userManager = $this->application->getContainer()->query('ServerContainer')->getUserManager();
		$results = $userManager->search('', 1, 0);

		if (!count($results)) {
			\OC::$server->getUserManager()->createUser('test', 'test');
		}
		$this->scannerFactory = new ScannerFactory(
				$this->config,
				$this->container->query('Logger')
		);
	}
	
	public function testRun(){
		$backgroundScanner = new BackgroundScanner(
				$this->scannerFactory,
				$this->l10n,
				$this->container->getServer()->getRootFolder(),
				$this->container->getServer()->getUserSession()
		);
		$bgScan = $backgroundScanner->run();
		$this->assertNull($bgScan);
	}
}
