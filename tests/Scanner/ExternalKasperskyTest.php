<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2021 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests\Scanner;

use OCA\Files_Antivirus\AppConfig;
use OCA\Files_Antivirus\Scanner\ExternalKaspersky;
use OCA\Files_Antivirus\Scanner\ScannerBase;
use OCA\Files_Antivirus\StatusFactory;
use OCP\Http\Client\IClientService;
use Psr\Log\LoggerInterface;

/**
 * @group DB
 */
class ExternalKasperskyTest extends ScannerBaseTest {
	protected function getScanner(): ScannerBase {
		if (!getenv('KASPERSKY_HOST') || !getenv('KASPERSKY_PORT')) {
			$this->markTestSkipped('Set KASPERSKY_HOST and KASPERSKY_PORT to enable kaspersky tests');
		}

		$logger = $this->createMock(LoggerInterface::class);
		$config = $this->createPartialMock(AppConfig::class, ['getAppValue']);
		$config->method('getAppValue')
			->willReturnCallback(function ($key) {
				switch ($key) {
					case 'av_host':
						return getenv('KASPERSKY_HOST');
					case 'av_port':
						return getenv('KASPERSKY_PORT');
					case 'av_scan_first_bytes':
						return '-1';
					default:
						return '';
				}
			});
		return new ExternalKaspersky($config, $logger, \OC::$server->get(StatusFactory::class), \OC::$server->get(IClientService::class));
	}
}
