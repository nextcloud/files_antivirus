<?php

/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\Tests;

use OCA\Files_Antivirus\AppConfig;
use OCA\Files_Antivirus\AppInfo\Application;
use OCP\AppFramework\IAppContainer;
use OCP\IDBConnection;
use OCP\IL10N;
use Test\TestCase;

abstract class TestBase extends TestCase {
	/** @var IDBConnection */
	protected $db;
	/** @var Application */
	protected $application;
	/** @var IAppContainer */
	protected $container;
	/** @var AppConfig|\PHPUnit_Framework_MockObject_MockObject */
	protected $config;
	/** @var IL10N */
	protected $l10n;


	protected function setUp(): void {
		parent::setUp();
		\OC_App::loadApp('files_antivirus');

		$this->db = \OC::$server->getDatabaseConnection();

		$this->application = new Application();
		$this->container = $this->application->getContainer();

		$this->config = $this->getMockBuilder(AppConfig::class)
			->disableOriginalConstructor()
			->setMethods(['getAvPath', 'getAvChunkSize', 'getAvMode', 'getAppValue', 'getAvHost', 'getAvPort'])
			->getMock();

		$this->config->expects($this->any())
			->method('getAvPath')
			->will($this->returnValue(__DIR__ . '/avir.sh'));
		$this->config->expects($this->any())
			->method('getAvChunkSize')
			->will($this->returnValue(1024));
		$this->config->expects($this->any())
			->method('getAvMode')
			->will($this->returnValue('executable'));
		$this->config->expects($this->any())
			->method('getAppValue')
			->will($this->returnCallback([$this, 'getAppValue']));
		$this->config->expects($this->any())
			->method('getAvHost')
			->will($this->returnValue('localhost'));
		$this->config->expects($this->any())
			->method('getAvPort')
			->will($this->returnValue('5555'));

		$this->l10n = $this->getMockBuilder(IL10N::class)
				->disableOriginalConstructor()
				->getMock();
		$this->l10n->method('t')->will($this->returnArgument(0));
	}

	public function getAppValue($methodName){
		switch ($methodName){
			case 'getAvPath':
				return  __DIR__ . '/avir.sh';
			case 'getAvMode':
				return 'executable';
		}
	}
}
