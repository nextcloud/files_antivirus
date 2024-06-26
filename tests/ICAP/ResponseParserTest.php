<?php

declare(strict_types=1);
/**
 * @copyright Copyright (c) 2024 Robin Appelman <robin@icewind.nl>
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
