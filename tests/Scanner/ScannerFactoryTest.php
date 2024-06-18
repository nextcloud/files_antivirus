<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace Scanner;

use OCA\Files_Antivirus\AppConfig;
use OCA\Files_Antivirus\Scanner\ScannerFactory;
use OCP\IConfig;
use OCP\IRequest;
use Test\TestCase;

/**
 * @group DB
 */
class ScannerFactoryTest extends TestCase {
	private IConfig $config;
	private AppConfig $appConfig;
	private IRequest $request;
	private ScannerFactory $scannerFactory;

	public function setUp(): void {
		$this->config = $this->createMock(IConfig::class);
		$this->config->method('getAppValue')
			->with('files_antivirus', 'av_mode', 'executable')
			->willReturn('daemon');

		$this->appConfig = new AppConfig($this->config);

		$this->request = $this->createMock(IRequest::class);

		$this->scannerFactory = new ScannerFactory(
			$this->appConfig,
			\OC::$server,
			$this->request,
		);
	}

	public function testGetScanner() {
		$instanceA = $this->scannerFactory->getScanner('/dev/null');
		$instanceB = $this->scannerFactory->getScanner('/dev/null');

		$this->assertNotSame($instanceA, $instanceB);
	}

}
