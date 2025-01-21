<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2021 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests\Scanner;

use OCA\Files_Antivirus\AppConfig;
use OCA\Files_Antivirus\Scanner\ICAP;
use OCA\Files_Antivirus\Scanner\ScannerBase;
use OCA\Files_Antivirus\StatusFactory;
use OCP\ICertificateManager;
use Psr\Log\LoggerInterface;

/**
 * @group DB
 */
class ICAPTest extends ScannerBaseTest {
	protected function getScanner(): ScannerBase {
		if (!getenv('ICAP_HOST') || !getenv('ICAP_PORT') || !getenv('ICAP_REQUEST') || !getenv('ICAP_HEADER') || !getenv('ICAP_MODE')) {
			$this->markTestSkipped('Set ICAP_HOST, ICAP_PORT, ICAP_REQUEST, ICAP_MODE and ICAP_HEADER to enable icap tests');
		}

		$logger = $this->createMock(LoggerInterface::class);
		$config = $this->createPartialMock(AppConfig::class, ['getAppValue', 'getAvIcapTls']);
		$config->method('getAppValue')
			->willReturnCallback(function ($key) {
				switch ($key) {
					case 'av_host':
						return getenv('ICAP_HOST');
					case 'av_port':
						return getenv('ICAP_PORT');
					case 'av_icap_request_service':
						return getenv('ICAP_REQUEST');
					case 'av_icap_response_header':
						return getenv('ICAP_HEADER');
					case 'av_icap_mode':
						return getenv('ICAP_MODE');
					case 'av_stream_max_length':
						return '26214400';
					case 'av_icap_chunk_size':
						return '1048576';
					case 'av_icap_connect_timeout':
						return '5';
					case 'av_scan_first_bytes':
						return '-1';
					default:
						return '';
				}
			});
		$config->method('getAvIcapTls')
			->willReturn(getenv('ICAP_TRANSPORT') === 'tls');
		return new ICAP($config, $logger, \OC::$server->get(StatusFactory::class), \OC::$server->get(ICertificateManager::class), false);
	}
}
