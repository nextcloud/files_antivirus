<?php
/**
 * Copyright (c) 2014 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\Tests;

use \OCA\Files_Antivirus\Db\RuleMapper;

/**
 * @group DB
 */
class StatusTest extends TestBase {
	
	// See OCA\Files_Antivirus\Status::init for details
	const TEST_CLEAN = 0;
	const TEST_INFECTED = 1;
	const TEST_ERROR = 40;
	
	protected $ruleMapper;


	public function setUp() {
		parent::setUp();
		$this->ruleMapper = new RuleMapper($this->db);
		$this->ruleMapper->deleteAll();
		$this->ruleMapper->populate();
	}
	
	public function testParseResponse(){
		// Testing status codes
		$testStatus = new \OCA\Files_Antivirus\Status();
		
		$testStatus->parseResponse('dummy : OK', self::TEST_CLEAN);
		$cleanScan = $testStatus->getNumericStatus();
		$this->assertEquals(\OCA\Files_Antivirus\Status::SCANRESULT_CLEAN, $cleanScan);
		$this->assertEquals("", $testStatus->getDetails());
		
		$scanOutput = "Thu Oct 28 13:02:19 2010 -> /tmp/kitten: Heuristics.Broken.Executable FOUND ";
		$testStatus->parseResponse($scanOutput, self::TEST_INFECTED);
		$infectedScan = $testStatus->getNumericStatus();
		$this->assertEquals(\OCA\Files_Antivirus\Status::SCANRESULT_INFECTED, $infectedScan);
		$this->assertEquals('Heuristics.Broken.Executable', $testStatus->getDetails());
		
		$testStatus->parseResponse('dummy', self::TEST_ERROR);
		$failedScan = $testStatus->getNumericStatus();
		$this->assertEquals(\OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED, $failedScan);
		$this->assertEquals('Unknown option passed.', $testStatus->getDetails());
		
		
		// Testing raw output (e.g. daemon mode)
		// Empty content means result is unknown
		$testStatus->parseResponse('');
		$failedScan2 = $testStatus->getNumericStatus();
		$this->assertEquals(\OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED, $failedScan2);
		$this->assertEquals('No matching rules. Please check antivirus rules.', $testStatus->getDetails());
		
		// No rules matched result is unknown too
		$testStatus->parseResponse('123dc');
		$failedScan3 = $testStatus->getNumericStatus();
		$this->assertEquals(\OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED, $failedScan3);
		$this->assertEquals('No matching rules. Please check antivirus rules.', $testStatus->getDetails());
		
		// File is clean
		$testStatus->parseResponse('Thu Oct 28 13:02:19 2010 -> /tmp/kitten : OK');
		$cleanScan2 = $testStatus->getNumericStatus();
		$this->assertEquals(\OCA\Files_Antivirus\Status::SCANRESULT_CLEAN, $cleanScan2);
		$this->assertEquals('', $testStatus->getDetails());
		
		// File is infected
		$testStatus->parseResponse('Thu Oct 28 13:02:19 2010 -> /tmp/kitten: Heuristics.Broken.Kitten FOUND');
		$infectedScan2 = $testStatus->getNumericStatus();
		$this->assertEquals(\OCA\Files_Antivirus\Status::SCANRESULT_INFECTED, $infectedScan2);
		$this->assertEquals('Heuristics.Broken.Kitten', $testStatus->getDetails());
	}
}
