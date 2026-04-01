<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2021 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests\Scanner;

use OCA\Files_Antivirus\AppInfo\ConfigLexicon;
use OCA\Files_Antivirus\Scanner\ScannerBase;
use OCA\Files_Antivirus\Status;
use OCP\AppFramework\Services\IAppConfig;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

abstract class ScannerBaseTestAbstract extends TestCase {
	protected IAppConfig&MockObject $config;

	abstract protected function getScanner(): ScannerBase;

	protected function setUp(): void {
		parent::setUp();
		$this->config = $this->createMock(IAppConfig::class);
		$this->config->method('getAppValueString')
			->willReturnCallback($this::configMock(...));
		$this->config->method('getAppValueInt')
			->willReturnCallback($this::configMock(...));
		$this->config->method('getAppValueBool')
			->willReturnCallback($this::configMock(...));
	}

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

	protected static function configMock(string $key): mixed {
		switch ($key) {
			case ConfigLexicon::AV_STREAM_MAX_LENGTH:
				return 26214400;
			case ConfigLexicon::AV_SCAN_FIRST_BYTES:
				return -1;
			default:
				return '';
		}
	}
}
