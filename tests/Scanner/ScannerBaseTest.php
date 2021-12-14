<?php

declare(strict_types=1);
/**
 * @copyright Copyright (c) 2021 Robin Appelman <robin@icewind.nl>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

namespace OCA\Files_Antivirus\Tests\Scanner;

use OCA\Files_Antivirus\Scanner\ScannerBase;
use OCA\Files_Antivirus\Status;
use Test\TestCase;

abstract class ScannerBaseTest extends TestCase {
	abstract protected function getScanner(): ScannerBase;

	public function testScanClean() {
		$scanner = $this->getScanner();
		$status = $scanner->scanString("foo");
		$this->assertEquals($status->getNumericStatus(), Status::SCANRESULT_CLEAN);
	}
	public function testScanEicar() {
		$eicar = base64_decode(str_rot13('JQICVINyDRSDJmEpHScLAGDbHS4cA0AQXGq9WRIWD0SFYIAHDH5RDIWRYHSBIRyJFIWIHl1HEIAHYHMWGRHuWRteFPb='));
		$scanner = $this->getScanner();
		$status = $scanner->scanString($eicar);
		$this->assertEquals($status->getNumericStatus(), Status::SCANRESULT_INFECTED);
	}
}
