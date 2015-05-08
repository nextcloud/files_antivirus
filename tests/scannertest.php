<?php
/**
 * Copyright (c) 2014 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

use \OCA\Files_Antivirus\Db\RuleMapper;
use \OCA\Files_Antivirus\Item;
use \OCA\Files_Antivirus\ScannerFactory;
use \OCA\Files_Antivirus\BackgroundScanner;

class Test_Files_Antivirus_ScannerTest extends \OCA\Files_Antivirus\Tests\Testbase {
	
	const TEST_CLEAN_FILENAME = 'foo.txt';
	const TEST_INFECTED_FILENAME = 'kitten.inf';

	protected $ruleMapper;
	protected $view;
	
	protected $cleanItem;
	protected $infectedItem;
	protected $scannerFactory;
	
	public function setUp() {
		parent::setUp();
		$this->view = $this->getMockBuilder('\OC\Files\View')
				->disableOriginalConstructor()
				->getMock()
		;
		
		$this->view->method('getOwner')->willReturn('Dummy');
		$this->view->method('file_exists')->willReturn(true);
		$this->view->method('filesize')->willReturn(42);
		
		$this->cleanItem = new Item($this->l10n, $this->view, self::TEST_CLEAN_FILENAME, 42);
		$this->infectedItem = new Item($this->l10n, $this->view, self::TEST_INFECTED_FILENAME, 42);

		$this->ruleMapper = new RuleMapper($this->db);
		$this->ruleMapper->deleteAll();
		$this->ruleMapper->populate();
		
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
	
	public function testCleanFile() {
		$handle = fopen(__DIR__ . '/data/foo.txt', 'r');
		$this->view->method('fopen')->willReturn($handle);
		$this->assertTrue($this->cleanItem->isValid());
		
		$scanner = $this->scannerFactory->getScanner();
		
		$scanner->scan($this->cleanItem);
		$cleanStatus = $scanner->getStatus();
		$this->assertInstanceOf('\OCA\Files_Antivirus\Status', $cleanStatus);
		$this->assertEquals(\OCA\Files_Antivirus\Status::SCANRESULT_CLEAN, $cleanStatus->getNumericStatus());
	}
	
	public function testNotExisting() {
		$this->setExpectedException('RuntimeException');
		
		$fileView = new \OC\Files\View('');
		$nonExistingItem = new Item($this->l10n, $fileView, 'non-existing.file', 42);
		$scanner = $this->scannerFactory->getScanner();
		$scanner->scan($nonExistingItem);
		$unknownStatus = $scanner->scan($nonExistingItem);
		$this->assertInstanceOf('\OCA\Files_Antivirus\Status', $unknownStatus);
		$this->assertEquals(\OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED, $unknownStatus->getNumericStatus());
	}
	
	public function testInfected() {
		$handle = fopen(__DIR__ . '/data/kitten.inf', 'r');
		$this->view->method('fopen')->willReturn($handle);
		$this->assertTrue($this->infectedItem->isValid());
		$scanner = $this->scannerFactory->getScanner();
		$scanner->scan($this->infectedItem);
		$infectedStatus = $scanner->getStatus();
		$this->assertInstanceOf('\OCA\Files_Antivirus\Status', $infectedStatus);
		$this->assertEquals(\OCA\Files_Antivirus\Status::SCANRESULT_INFECTED, $infectedStatus->getNumericStatus());
	}
}
