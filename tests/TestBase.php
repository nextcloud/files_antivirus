<?php

/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_antivirus\Tests;

use OCA\Files_Antivirus\AppConfig;
use OCA\Files_Antivirus\AppInfo\Application;

abstract class TestBase extends \PHPUnit_Framework_TestCase {

	protected $db;
	protected $application;
	protected $container;
	/** @var AppConfig|\PHPUnit_Framework_MockObject_MockObject */
	protected $config;
	protected $l10n;
	

	public function setUp(){
		parent::setUp();
		\OC_App::loadApp('files_antivirus');
		
		$this->db = \OC::$server->getDatabaseConnection();
		
		$this->application = new Application();
		$this->container = $this->application->getContainer();
		
		$this->config = $this->getMockBuilder(AppConfig::class)
				->disableOriginalConstructor()
				->getMock()
		;
		$this->config->method('__call')
			->will($this->returnCallback(array($this, 'getAppValue')));
		
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
			case 'getAvChunkSize':
				return 1024;
			case 'getAvMode':
				return 'executable';
		}
	}
}
