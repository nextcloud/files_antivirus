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
use Psr\Log\LoggerInterface;

class ExternalKaspersky extends ScannerBase {
	private int $chunkSize;
	private ?HttpRequest $httpRequest = null;
	/** @var resource|null $stream */
	private $stream = null;
	private float $requestStartTime = 0;
	private int $requestBodySize = 0;

	public const BODY_PREFIX = '{"object":"';
	public const BODY_SUFFIX = '"}';

	public function __construct(
		IAppConfig $appConfig,
		LoggerInterface $logger,
		StatusFactory $statusFactory,
		private readonly ICertificateManager $certificateManager,
		private readonly bool $verifyTlsPeer = true,
	) {
		parent::__construct($appConfig, $logger, $statusFactory);
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
		$this->httpRequest = null;

		// if the size isn't known, we need to buffer the entire file before we can send it,
		// the connection is only opened then so it doesn't idle while the file is buffered
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
		$this->stream = $this->getTransport()->connect();
		$this->requestStartTime = microtime(true);
		$this->requestBodySize = $encodedSize;

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
		if ($this->httpRequest?->getWriteError() !== null) {
			return;
		}

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
		try {
			if (!$this->httpRequest) {
				$this->httpRequest = $this->startRequest($size);
			}

			if ($this->httpRequest->getWriteError() === null) {
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
			}
			$response = $this->httpRequest->finish();
		} catch (\RuntimeException $e) {
			$this->handleRequestError($e);
			return;
		}

		$this->handleResponse($response);
	}

	/**
	 * Report the file as unchecked, with enough context to tell a scanner side limit or timeout from a network issue
	 */
	private function handleRequestError(\RuntimeException $e): void {
		$message = 'Kaspersky scan failed: ' . $e->getMessage();
		if ($this->httpRequest !== null) {
			$writeError = $this->httpRequest->getWriteError();
			$message .= ' (' . $this->getRequestProgress() . ($writeError !== null ? ', sending failed: ' . $writeError : '') . ')';
		}

		$this->logger->error($message, ['exception' => $e, 'app' => 'files_antivirus']);
		$this->status->setNumericStatus(Status::SCANRESULT_UNCHECKED);
		$this->status->setDetails($message);
	}

	private function getRequestProgress(): string {
		return sprintf(
			'sent %d of %d bytes in %.1f seconds',
			$this->httpRequest?->getBodyBytesSent() ?? 0,
			$this->requestBodySize,
			microtime(true) - $this->requestStartTime,
		);
	}

	private function handleResponse(HttpResponse $response): void {
		$context = '(' . $this->getRequestProgress() . ')';
		$responseBody = (string)stream_get_contents($response->getBody());

		if ($response->getStatus()->getCode() > 299) {
			$details = 'Error(' . $response->getStatus()->getStatus() . '): ' . $responseBody;
			$this->logger->error('Kaspersky responded with HTTP ' . $response->getStatus()->getCode() . ' ' . $context . ': ' . substr($responseBody, 0, 1000), ['app' => 'files_antivirus']);
			$this->status->setNumericStatus(Status::SCANRESULT_UNCHECKED);
			$this->status->setDetails($details);
			return;
		};

		$this->logger->debug('Kaspersky responded ' . $context . ': ' . substr($responseBody, 0, 1000), ['app' => 'files_antivirus']);

		$responseBody = json_decode($responseBody, true);
		if (!is_array($responseBody) || !is_string($responseBody['scanResult'] ?? null)) {
			$message = 'Kaspersky scan failed: invalid response ' . $context;
			$this->logger->error($message, ['app' => 'files_antivirus']);
			$this->status->setNumericStatus(Status::SCANRESULT_UNCHECKED);
			$this->status->setDetails($message);
			return;
		}
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
