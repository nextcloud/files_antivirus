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
use Psr\Log\LoggerInterface;
use Test\TestCase;

class ExternalKasperskyConnectionTest extends TestCase {
	/** @var resource */
	private $server;
	private int $port;

	protected function setUp(): void {
		parent::setUp();
		$server = stream_socket_server('tcp://127.0.0.1:0', $errorCode, $errorMessage);
		$this->assertNotFalse($server, $errorMessage);
		$this->server = $server;
		$this->port = (int)substr(strrchr(stream_socket_get_name($server, false), ':'), 1);
	}

	protected function tearDown(): void {
		if (is_resource($this->server)) {
			fclose($this->server);
		}
		parent::tearDown();
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
			$this->createMock(LoggerInterface::class),
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
}
