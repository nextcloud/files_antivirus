<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace Scanner;

use OCA\Files_Antivirus\AppInfo\ConfigLexicon;
use OCA\Files_Antivirus\Scanner\ScannerFactory;
use OCP\AppFramework\Services\IAppConfig;
use OCP\IRequest;
use PHPUnit\Framework\Attributes\Group;
use Test\TestCase;

#[Group('DB')]
class ScannerFactoryTest extends TestCase {
	private IAppConfig $appConfig;
	private IRequest $request;
	private ScannerFactory $scannerFactory;

	public function setUp(): void {
		$this->appConfig = $this->createMock(IAppConfig::class);
		$this->appConfig->method('getAppValueString')
			->willReturnMap([
				[ConfigLexicon::AV_MODE, '', 'daemon'],
			]);

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
