<?php

/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_antivirus\Tests;

use OCA\Files_Antivirus\AppInfo\Application;

abstract class TestBase extends \PHPUnit_Framework_TestCase {

	protected $db;
	protected $application;
	protected $container;
	protected $config;
	protected $streamConfig;
	protected $l10n;
	

	public function setUp(){
		parent::setUp();
		\OC_App::enable('files_antivirus');
		
		$this->db = \OC::$server->getDb();
		
		$this->application = new Application();
		$this->container = $this->application->getContainer();
		
		$this->config = $this->getMockBuilder('\OCA\Files_Antivirus\AppConfig')
				->disableOriginalConstructor()
				->getMock()
		;
		$this->config->method('__call')
			->will($this->returnCallback(array($this, 'getAppValue')));

		$this->streamConfig = $this->getMockBuilder('\OCA\Files_Antivirus\AppConfig')
			->disableOriginalConstructor()
			->getMock()
		;
		$this->streamConfig->method('__call')
			->will($this->returnCallback(array($this, 'getAppStreamValue')));

		$this->l10n = $this->getMockBuilder('\OCP\IL10N')
				->disableOriginalConstructor()
				->getMock()
		;
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
	public function getAppStreamValue($methodName){
		switch ($methodName){
			case 'getAvHost':
				return '127.0.0.1';
			case 'getAvPort':
				return 5555;
			case 'getAvStreamMaxLength':
				return DummyClam::TEST_STREAM_SIZE;
			case 'getAvMode':
				return 'daemon';
		}
	}
}
