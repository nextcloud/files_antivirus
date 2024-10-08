<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests\ICAP;

use OCA\Files_Antivirus\ICAP\ICAPClient;
use Test\TestCase;

class ICAPClientTest extends TestCase {
	public function testConnect_ShouldThrowRuntimeException() {
		$this->expectException(\RuntimeException::class);
		$this->expectExceptionMessageMatches('/Cannot connect to "tcp\:\/\/nothinghere\:8080"\: .*/');
		$icapClient = new ICAPClient('nothinghere', 8080, 2);
		$icapClient->respmod('myservice', [], [], []);
	}
}
