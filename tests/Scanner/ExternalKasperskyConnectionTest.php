<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests\Scanner;

use OCA\Files_Antivirus\AppInfo\ConfigLexicon;
use OCA\Files_Antivirus\Scanner\ExternalKaspersky;
use OCA\Files_Antivirus\Status;
use OCA\Files_Antivirus\StatusFactory;
use OCP\AppFramework\Services\IAppConfig;
use OCP\ICertificateManager;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class ExternalKasperskyConnectionTest extends TestCase {
	/** @var resource */
	private $server;
	private int $port;
	/** @var resource|null */
	private $serverProcess = null;
	private LoggerInterface&MockObject $logger;

	protected function setUp(): void {
		parent::setUp();
		$server = stream_socket_server('tcp://127.0.0.1:0', $errorCode, $errorMessage);
		$this->assertNotFalse($server, $errorMessage);
		$this->server = $server;
		$this->port = self::getPort($server);
		$this->logger = $this->createMock(LoggerInterface::class);
	}

	protected function tearDown(): void {
		if (is_resource($this->server)) {
			fclose($this->server);
		}
		if (is_resource($this->serverProcess)) {
			proc_terminate($this->serverProcess);
			proc_close($this->serverProcess);
		}
		parent::tearDown();
	}

	/**
	 * @param resource $server
	 */
	private static function getPort($server): int {
		return (int)substr(strrchr(stream_socket_get_name($server, false), ':'), 1);
	}

	/**
	 * Serve a single request in a separate process, the response is sent once the full request body is received
	 *
	 * @param string $response raw response, an empty string closes the connection without a response
	 */
	private function serveOnce(string $response): void {
		$code = <<<'PHP'
			$server = stream_socket_server('tcp://127.0.0.1:0');
			echo substr(strrchr(stream_socket_get_name($server, false), ':'), 1), "\n";
			$connection = stream_socket_accept($server, 10);
			$contentLength = 0;
			while (($line = fgets($connection)) !== false && trim($line) !== '') {
				if (stripos($line, 'content-length:') === 0) {
					$contentLength = (int)trim(substr($line, 15));
				}
			}
			while ($contentLength > 0 && ($data = fread($connection, $contentLength)) !== false && $data !== '') {
				$contentLength -= strlen($data);
			}
			fwrite($connection, base64_decode($argv[1]));
			fclose($connection);
			PHP;
		$this->serverProcess = proc_open(
			[PHP_BINARY, '-r', $code, base64_encode($response)],
			[1 => ['pipe', 'w']],
			$pipes,
		);
		$this->assertIsResource($this->serverProcess);
		$this->port = (int)fgets($pipes[1]);
		$this->assertGreaterThan(0, $this->port);
	}

	private function getScanner(?int $size): ExternalKaspersky {
		$config = $this->createMock(IAppConfig::class);
		$config->method('getAppValueString')->willReturnCallback(fn (string $key) => match ($key) {
			ConfigLexicon::AV_HOST => '127.0.0.1',
			default => '',
		});
		$config->method('getAppValueInt')->willReturnCallback(fn (string $key) => match ($key) {
			ConfigLexicon::AV_PORT => $this->port,
			ConfigLexicon::AV_ICAP_CONNECT_TIMEOUT => 1,
			ConfigLexicon::AV_STREAM_MAX_LENGTH => 26214400,
			ConfigLexicon::AV_SCAN_FIRST_BYTES => -1,
			default => 0,
		});

		$scanner = new ExternalKaspersky(
			$config,
			$this->logger,
			Server::get(StatusFactory::class),
			$this->createMock(ICertificateManager::class),
		);
		if ($size !== null) {
			$scanner->setSize($size);
		}
		return $scanner;
	}

	public function testConnectsOnlyOnceTheDataIsBufferedForUnknownSize(): void {
		$scanner = $this->getScanner(null);
		$scanner->initScanner();
		$scanner->onAsyncData(str_repeat('a', 1024 * 1024));

		$this->assertFalse(@stream_socket_accept($this->server, 0), 'The scanner must not connect before the size is known');
	}

	public function testConnectsAndStreamsImmediatelyForKnownSize(): void {
		$scanner = $this->getScanner(3);
		$scanner->initScanner();

		$connection = @stream_socket_accept($this->server, 1);
		$this->assertNotFalse($connection);
		$this->assertStringStartsWith('POST /api/v3.0/scanmemory HTTP/1.1', (string)fgets($connection));
		fclose($connection);
	}

	public function testUnreachableScannerForUnknownSizeIsReportedUnchecked(): void {
		fclose($this->server);

		$scanner = $this->getScanner(null);
		$status = $scanner->scanString('foo');

		$this->assertSame(Status::SCANRESULT_UNCHECKED, $status->getNumericStatus());
		$this->assertStringContainsString('Cannot connect', (string)$status->getDetails());
	}

	public static function sizeProvider(): array {
		return [
			'unknown size' => [null],
			'known size' => [3],
		];
	}

	#[DataProvider('sizeProvider')]
	public function testCleanResponse(?int $size): void {
		$body = '{"object":"","scanResult":"CLEAN"}';
		$this->serveOnce("HTTP/1.1 200 OK\r\nContent-Length: " . strlen($body) . "\r\n\r\n" . $body);
		$this->logger->expects($this->never())->method('error');

		$status = $this->getScanner($size)->scanString('foo');

		$this->assertSame(Status::SCANRESULT_CLEAN, $status->getNumericStatus());
	}

	#[DataProvider('sizeProvider')]
	public function testConnectionClosedWithoutResponseIsReportedUnchecked(?int $size): void {
		$this->serveOnce('');
		$this->logger->expects($this->once())->method('error')
			->with($this->stringContains('the connection was closed without a response (sent 17 of 17 bytes in'));

		$status = $this->getScanner($size)->scanString('foo');

		$this->assertSame(Status::SCANRESULT_UNCHECKED, $status->getNumericStatus());
		$this->assertStringStartsWith('Kaspersky scan failed: Error reading response from server', (string)$status->getDetails());
	}

	public function testErrorResponseIsLogged(): void {
		$this->serveOnce("HTTP/1.1 413 Payload Too Large\r\nContent-Length: 8\r\n\r\ntoo big!");
		$this->logger->expects($this->once())->method('error')
			->with($this->stringContains('Kaspersky responded with HTTP 413 (sent 17 of 17 bytes in'));

		$status = $this->getScanner(null)->scanString('foo');

		$this->assertSame(Status::SCANRESULT_UNCHECKED, $status->getNumericStatus());
		$this->assertSame('Error(Payload Too Large): too big!', $status->getDetails());
	}

	public function testInvalidResponseIsReportedUnchecked(): void {
		$this->serveOnce("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nnot json!");
		$this->logger->expects($this->once())->method('error')
			->with($this->stringContains('Kaspersky scan failed: invalid response'));

		$status = $this->getScanner(null)->scanString('foo');

		$this->assertSame(Status::SCANRESULT_UNCHECKED, $status->getNumericStatus());
	}
}
