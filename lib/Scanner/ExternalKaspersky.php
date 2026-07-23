<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2020 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Scanner;

use OCA\Files_Antivirus\AppInfo\ConfigLexicon;
use OCA\Files_Antivirus\Net\Http\HttpRequest;
use OCA\Files_Antivirus\Net\Http\HttpResponse;
use OCA\Files_Antivirus\Net\TcpClient;
use OCA\Files_Antivirus\Net\TlsClient;
use OCA\Files_Antivirus\Status;
use OCA\Files_Antivirus\StatusFactory;
use OCP\AppFramework\Services\IAppConfig;
use OCP\ICertificateManager;
use OCP\IConfig;
use Psr\Log\LoggerInterface;

class ExternalKaspersky extends ScannerBase {
	private int $chunkSize;
	private ?HttpRequest $httpRequest = null;
	/** @var resource|null $stream */
	private $stream = null;

	public const BODY_PREFIX = '{"object":"';
	public const BODY_SUFFIX = '"}';

	public function __construct(
		IConfig $config,
		IAppConfig $appConfig,
		LoggerInterface $logger,
		StatusFactory $statusFactory,
		private readonly ICertificateManager $certificateManager,
		private readonly bool $verifyTlsPeer = true,
	) {
		parent::__construct($config, $appConfig, $logger, $statusFactory);
		// this is intentionally a multiple of 3 to hit the happy path for base64 chunking
		// and a multiple of 8k, which is php's internal chunk size
		$this->chunkSize = 30 * 8 * 1024;
	}

	private function getTransport(): TcpClient {
		$avHost = $this->appConfig->getAppValueString(ConfigLexicon::AV_HOST);
		$avPort = $this->appConfig->getAppValueInt(ConfigLexicon::AV_PORT);
		$timout = $this->appConfig->getAppValueInt(ConfigLexicon::AV_ICAP_CONNECT_TIMEOUT);

		if (!($avHost && $avPort)) {
			throw new \RuntimeException('The Kaspersky port and host are not set up.');
		}

		if (str_contains($avHost, '://')) {
			[$protocol, $avHost] = explode('://', $avHost, 2);
			$tls = $protocol === 'https';
		} else {
			$tls = false;
		}
		if ($tls) {
			return new TlsClient($avHost, $avPort, $timout, $this->certificateManager, $this->verifyTlsPeer);
		} else {
			return new TcpClient($avHost, $avPort, $timout);
		}
	}

	#[\Override]
	public function initScanner(): void {
		parent::initScanner();

		$transport = $this->getTransport();
		$this->stream = $transport->connect();

		// if the size isn't known, we need to buffer the entire file before we can send it
		if ($this->size !== null) {
			$this->httpRequest = $this->startRequest($this->size);
		}

		$this->writeHandle = fopen('php://temp', 'w+');
	}

	private function startRequest(int $size): HttpRequest {
		$encodedSize = strlen(self::BODY_PREFIX)
			+ (4 * (int)ceil($size / 3))
			+ strlen(self::BODY_SUFFIX);
		$avHost = $this->appConfig->getAppValueString(ConfigLexicon::AV_HOST);

		$request = new HttpRequest(
			$this->stream,
			$avHost,
			'POST',
			'/api/v3.0/scanmemory',
			[
				'content-type' => 'application/json',
				'content-length' => $encodedSize,
			]
		);
		$request->init();
		$request->write(self::BODY_PREFIX);
		return $request;
	}

	#[\Override]
	protected function writeChunk(string $chunk): void {
		// if the size isn't known, we couldn't start the request before the write is complete
		// and we need to buffer the entire file before we can send it
		if ($this->httpRequest && ftell($this->writeHandle) >= $this->chunkSize) {
			$body = $this->flushBuffer();

			// send data in multiple of 3 bytes to fit the base64 encoding chunking
			$chunkSize = (int)floor(strlen($body) / 3) * 3;
			$writeChunk = substr($body, 0, $chunkSize);

			// keep the leftover
			fwrite($this->writeHandle, substr($body, $chunkSize));

			$this->httpRequest->write(base64_encode($writeChunk));
		}
		$this->writeRaw($chunk);
	}

	private function flushBuffer(): string {
		rewind($this->writeHandle);
		/** @var string $body */
		$body = \stream_get_contents($this->writeHandle);
		ftruncate($this->writeHandle, 0);
		return $body;
	}

	#[\Override]
	protected function shutdownScanner(): void {
		$size = ftell($this->writeHandle);
		if (!$this->httpRequest) {
			$this->httpRequest = $this->startRequest($size);
		}

		rewind($this->writeHandle);
		$chunkSize = (int)floor($this->chunkSize / 3) * 3;
		while (($chunk = fread($this->writeHandle, $chunkSize)) !== false) {
			if ($chunk === '') {
				break;
			}
			$enc = base64_encode($chunk);
			$this->httpRequest->write($enc);
		}
		$this->httpRequest->write(self::BODY_SUFFIX);
		$response = $this->httpRequest->finish();

		$this->handleResponse($response);
	}

	private function handleResponse(HttpResponse $response): void {
		if ($response->getStatus()->getCode() > 299) {
			$this->status->setNumericStatus(Status::SCANRESULT_UNCHECKED);
			$body = stream_get_contents($response->getBody());
			$this->status->setDetails('Error(' . $response->getStatus()->getStatus() . '): ' . $body);
			return;
		};
		$responseBody = stream_get_contents($response->getBody());

		$responseBody = json_decode($responseBody, true);
		$scanResult = $responseBody['scanResult'];

		if (str_starts_with($scanResult, 'CLEAN') && $this->status->getNumericStatus() != Status::SCANRESULT_INFECTED) {
			$this->status->setNumericStatus(Status::SCANRESULT_CLEAN);
		} elseif (str_starts_with($scanResult, 'NON_SCANNED') && $this->status->getNumericStatus() != Status::SCANRESULT_INFECTED) {
			if ($scanResult === 'NON_SCANNED (PASSWORD PROTECTED)') {
				// if we can't scan the file at all, there is no use in trying to scan it again later
				$this->status->setNumericStatus(Status::SCANRESULT_UNSCANNABLE);
			} else {
				$this->status->setNumericStatus(Status::SCANRESULT_UNCHECKED);
			}
			$this->status->setDetails($scanResult);
		} else {
			$this->status->setNumericStatus(Status::SCANRESULT_INFECTED);
			if (str_starts_with($scanResult, 'DETECT ')) {
				$scanResult = substr($scanResult, 7);
			}
			if (isset($responseBody['detectionName'])) {
				$scanResult .= ' ' . $responseBody['detectionName'];
			}
			$this->status->setDetails($scanResult);
		}
	}
}
