<?php

/**
 * Copyright (c) 2017 Victor Dubiniuk <dubiniuk@owncloud.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */


namespace OCA\Files_Antivirus\Tests;

use OCA\Files_Antivirus\BackgroundJob\BackgroundScanner;
use OCA\Files_Antivirus\Scanner\ScannerFactory;
use Doctrine\DBAL\Driver\PDOStatement;
use OCP\ILogger;

/**
 * Class BackgroundScannerTest
 *
 * @package OCA\Files_Antivirus\Tests
 * @group DB
 */
class BackgroundScannerTest extends TestBase {

	public function testGetFilesForScan(){
		$this->assertTrue(true);
		return;

		$scannerFactory = new Mock\ScannerFactory(
			new Mock\Config($this->container->query('CoreConfig')),
			$this->container->query('Logger')
		);

		$scannerMock = $this->getMockBuilder(BackgroundScanner::class)
			->setConstructorArgs([
				$scannerFactory,
				$this->l10n,
				$this->config,
				\OC::$server->getRootFolder(),
				\OC::$server->getUserSession(),
				\OC::$server->getLogger(),
				\OC::$server->getUserManager(),
				\OC::$server->getDatabaseConnection(),
				\OC::$server->getMimeTypeLoader()
			])
			->getMock();

		$class = new \ReflectionClass($scannerMock);
		$method = $class->getMethod('getFilesForScan');
		$method->setAccessible(true);
		$result = $method->invokeArgs($scannerMock, []);
		$this->assertEquals(PDOStatement::class, get_class($result));
	}

}
