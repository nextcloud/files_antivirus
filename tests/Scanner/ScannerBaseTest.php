<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2021 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests\Scanner;

use OCA\Files_Antivirus\Scanner\ScannerBase;
use OCA\Files_Antivirus\Status;
use Test\TestCase;

abstract class ScannerBaseTest extends TestCase {
	abstract protected function getScanner(): ScannerBase;

	public function testScanClean() {
		$scanner = $this->getScanner();
		$status = $scanner->scanString('foo');
		$this->assertEquals($status->getNumericStatus(), Status::SCANRESULT_CLEAN);
	}
	public function testScanEicar() {
		$eicar = base64_decode(str_rot13('JQICVINyDRSDJmEpHScLAGDbHS4cA0AQXGq9WRIWD0SFYIAHDH5RDIWRYHSBIRyJFIWIHl1HEIAHYHMWGRHuWRteFPb='));
		$scanner = $this->getScanner();
		$status = $scanner->scanString($eicar);
		$this->assertEquals($status->getNumericStatus(), Status::SCANRESULT_INFECTED);
	}
}
