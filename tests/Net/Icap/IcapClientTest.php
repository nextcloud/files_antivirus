<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests\Net\Icap;

use OCA\Files_Antivirus\Net\Icap\IcapClient;
use OCA\Files_Antivirus\Net\TcpClient;
use Test\TestCase;

class IcapClientTest extends TestCase {
	public function testConnect_ShouldThrowRuntimeException() {
		$this->expectException(\RuntimeException::class);
		$this->expectExceptionMessageMatches('/Cannot connect to "tcp\:\/\/nothinghere\:8080"\: .*/');
		$transport = new TcpClient('nothinghere', 8080, 1);
		$icapClient = new IcapClient($transport);
		$icapClient->respmod('myservice', [], [], []);
	}
}
