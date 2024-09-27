<?php

/**
 * SPDX-FileCopyrightText: 2017-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2014-2016 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests;

use OCA\Files_Antivirus\Db\RuleMapper;
use Psr\Log\LoggerInterface;

/**
 * @group DB
 */
class StatusTest extends TestBase {

	// See OCA\Files_Antivirus\Status::init for details
	public const TEST_CLEAN = 0;
	public const TEST_INFECTED = 1;
	public const TEST_ERROR = 40;

	protected RuleMapper $ruleMapper;
	private bool $blockUnscannable = false;

	protected function setUp(): void {
		parent::setUp();
		$this->ruleMapper = new RuleMapper($this->db);
		$this->ruleMapper->deleteAll();
		$this->ruleMapper->populate();
		$this->config->method('getAvBlockUnscannable')
			->willReturnCallback(function () {
				return $this->blockUnscannable;
			});
	}

	public function testParseResponse() {
		// Testing status codes
		$testStatus = new \OCA\Files_Antivirus\Status(
			$this->ruleMapper,
			$this->createMock(LoggerInterface::class),
			$this->config,
		);

		$testStatus->parseResponse('dummy : OK', self::TEST_CLEAN);
		$cleanScan = $testStatus->getNumericStatus();
		$this->assertEquals(\OCA\Files_Antivirus\Status::SCANRESULT_CLEAN, $cleanScan);
		$this->assertEquals('', $testStatus->getDetails());

		$scanOutput = 'Thu Oct 28 13:02:19 2010 -> /tmp/kitten: Heuristics.Broken.Executable FOUND ';
		$testStatus->parseResponse($scanOutput, self::TEST_INFECTED);
		$infectedScan = $testStatus->getNumericStatus();
		$this->assertEquals(\OCA\Files_Antivirus\Status::SCANRESULT_INFECTED, $infectedScan);
		$this->assertEquals('Heuristics.Broken.Executable', $testStatus->getDetails());

		$testStatus->parseResponse('dummy', self::TEST_ERROR);
		$failedScan = $testStatus->getNumericStatus();
		$this->assertEquals(\OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED, $failedScan);
		$this->assertEquals('Unknown option passed.', $testStatus->getDetails());


		// Testing raw output (e.g. daemon mode)
		$assertDetailsWithResponse = function ($response) use ($testStatus) {
			$expected = "No matching rule for response [$response]. Please check antivirus rules configuration.";
			$this->assertEquals($expected, $testStatus->getDetails());
		};

		// Empty content means result is unknown
		$testStatus->parseResponse('');
		$failedScan2 = $testStatus->getNumericStatus();
		$this->assertEquals(\OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED, $failedScan2);
		$assertDetailsWithResponse('');

		// No rules matched result is unknown too
		$testStatus->parseResponse('123dc');
		$failedScan3 = $testStatus->getNumericStatus();
		$this->assertEquals(\OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED, $failedScan3);
		$assertDetailsWithResponse('123dc');

		// Raw result is added to details when no rule matched (only ASCII text range 32..126 excluding '`').
		for ($c = 0; $c < 256; $c++) {
			$testStatus->parseResponse(chr($c));
			$expected = $c < 32 || $c > 126 || chr($c) == '`' ? '' : chr($c);
			$assertDetailsWithResponse($expected);
		}

		// Raw result in details is truncated at 512 chars.
		$testStatus->parseResponse(str_repeat('a', 512));
		$assertDetailsWithResponse(str_repeat('a', 512));
		$testStatus->parseResponse(str_repeat('a', 513));
		$assertDetailsWithResponse(str_repeat('a', 509) . '...');

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
