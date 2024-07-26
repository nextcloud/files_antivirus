<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests\ICAP;

use OCA\Files_Antivirus\ICAP\ResponseParser;
use Test\TestCase;

class ResponseParserTest extends TestCase {
	private function parseResponse(string $responsePath) {
		return (new ResponseParser())->read_response(fopen($responsePath, 'r'));
	}

	public function testParse403() {
		$response = $this->parseResponse(__DIR__ . '/../data/icap/403-response.txt');
		$this->assertEquals('HTTP/1.1 403 Forbidden', $response->getResponseHeaders()['HTTP_STATUS']);
	}

	public function testParseNullBody() {
		$response = $this->parseResponse(__DIR__ . '/../data/icap/null-body.txt');
		$this->assertEquals([], $response->getResponseHeaders());
	}
}
