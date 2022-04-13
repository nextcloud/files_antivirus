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

use OCA\Files_Antivirus\AppConfig;
use OCA\Files_Antivirus\Scanner\ICAP;
use OCA\Files_Antivirus\Scanner\ScannerBase;
use OCA\Files_Antivirus\StatusFactory;
use OCP\ILogger;

/**
 * @group DB
 */
class ICAPTest extends ScannerBaseTest {
	protected function getScanner(): ScannerBase {
		if (!getenv('ICAP_HOST') || !getenv('ICAP_PORT') || !getenv('ICAP_REQUEST') || !getenv('ICAP_HEADER')) {
			$this->markTestSkipped("Set ICAP_HOST, ICAP_PORT, ICAP_REQUEST and ICAP_HEADER to enable icap tests");
		}

		$logger = $this->createMock(ILogger::class);
		$config = $this->createPartialMock(AppConfig::class, ['getter']);
		$config->method('getter')
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
					case 'av_stream_max_length':
						return '26214400';
					case 'av_icap_chunk_size':
						return '1048576';
					case 'av_icap_connect_timeout':
						return '5';
				}
			});
		return new ICAP($config, $logger, \OC::$server->get(StatusFactory::class));
	}
}
