<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

use \OCA\Files_Antivirus\Db\RuleMapper;
use \OCA\Files_Antivirus\Item;
use \OCA\Files_Antivirus\ScannerFactory;
use \OCA\Files_Antivirus\BackgroundScanner;

class Test_Files_Antivirus_Cron_TaskTest extends \OCA\Files_Antivirus\Tests\Testbase {
	public function setUp(){
		parent::setUp();
		//Bgscanner requires at least one user on the current instance
		$userManager = $this->application->getContainer()->query('ServerContainer')->getUserManager();
		$results = $userManager->search('', 1, 0);

		if (!count($results)) {
			\OC_User::createUser('test', 'test');
		}
		$this->scannerFactory = new ScannerFactory(
				$this->config,
				$this->container->query('Logger')
		);
	}
	
	public function testRun(){
		$backgroudScanner = new BackgroundScanner(
				$this->scannerFactory,
				$this->container->query('ServerContainer')->getUserManager(),
				$this->l10n
		);
		$bgScan = $backgroudScanner->run();
		$this->assertNull($bgScan);
	}
}
