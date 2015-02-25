<?php

/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\Tests;

abstract class Testbase extends \PHPUnit_Framework_TestCase {

	protected $db;
	protected $config;
	protected $l10n;

	public function setUp(){
		parent::setUp();
		\OC_App::enable('files_antivirus');
		$this->db = \OC::$server->getDb();
		$this->config = $this->getMockBuilder('\OCA\Files_Antivirus\Appconfig')
				->disableOriginalConstructor()
				->getMock()
		;
		
		$this->l10n = \OCP\Util::getL10N('files_antivirus');
		
		$this->config->method('__call')
			->will($this->returnCallback(array($this, 'getAppValue')));
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
