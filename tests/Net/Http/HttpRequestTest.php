<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests\Net\Http;

use OCA\Files_Antivirus\Net\Http\HttpRequest;
use OCA\Files_Antivirus\Net\Http\HttpResponseParser;
use RuntimeException;
use Test\TestCase;

class HttpRequestTest extends TestCase {
	/**
	 * @return array{resource, resource}
	 */
	private function getSocketPair(): array {
		$pair = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
		$this->assertIsArray($pair);
		return $pair;
	}

	public function testCountsSentBodyBytes(): void {
		[$client, $server] = $this->getSocketPair();
		$request = new HttpRequest($client, 'localhost', 'POST', '/', ['content-length' => 6]);
		$request->init();
		$request->write('foo');
		$request->write('bar');

		$this->assertSame(6, $request->getBodyBytesSent());
		$this->assertNull($request->getWriteError());
		$this->assertStringEndsWith("\r\n\r\nfoobar", (string)fread($server, 8192));
	}

	public function testWriteFailureIsRecordedAndFurtherDataDiscarded(): void {
		[$client, $server] = $this->getSocketPair();
		$request = new HttpRequest($client, 'localhost', 'POST', '/', ['content-length' => 6]);
		$request->init();
		$request->write('foo');
		fclose($server);
		$request->write('bar');
		$request->write('baz');

		$this->assertSame(3, $request->getBodyBytesSent());
		$this->assertNotNull($request->getWriteError());
	}

	public function testReadingClosedConnection(): void {
		[$client, $server] = $this->getSocketPair();
		fclose($server);

		$this->expectException(RuntimeException::class);
		$this->expectExceptionMessage('Error reading response from server: the connection was closed without a response');
		(new HttpResponseParser())->readResponse($client);
	}

	public function testReadingTimesOut(): void {
		[$client, $server] = $this->getSocketPair();
		stream_set_timeout($client, 0, 10000);

		try {
			$this->expectException(RuntimeException::class);
			$this->expectExceptionMessage('Error reading response from server: timed out waiting for the response');
			(new HttpResponseParser())->readResponse($client);
		} finally {
			fclose($server);
		}
	}
}
