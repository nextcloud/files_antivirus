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
			$this->markTestSkipped("Set KASPERSKY_HOST and KASPERSKY_PORT to enable kaspersky tests");
		}

		$logger = $this->createMock(LoggerInterface::class);
		$config = $this->createPartialMock(AppConfig::class, ['getter']);
		$config->method('getAppValue')
			->willReturnCallback(function ($key) {
				switch ($key) {
					case 'av_host':
						return getenv('KASPERSKY_HOST');
					case 'av_port':
						return getenv('KASPERSKY_PORT');
					case 'av_scan_first_bytes':
						return -1;
					default:
						return '';
				}
			});
		return new ExternalKaspersky($config, $logger, \OC::$server->get(StatusFactory::class), \OC::$server->get(IClientService::class));
	}
}
