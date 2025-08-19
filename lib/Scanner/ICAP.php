<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2020 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Scanner;

use OCA\Files_Antivirus\AppConfig;
use OCA\Files_Antivirus\ICAP\ICAPClient;
use OCA\Files_Antivirus\ICAP\ICAPRequest;
use OCA\Files_Antivirus\ICAP\ICAPTlsClient;
use OCA\Files_Antivirus\Status;
use OCA\Files_Antivirus\StatusFactory;
use OCP\ICertificateManager;
use Psr\Log\LoggerInterface;

class ICAP extends ScannerBase {
	/** @var ICAPClient::MODE_REQ_MOD|ICAPClient::MODE_RESP_MOD */
	private string $mode;
	private ICAPClient $icapClient;
	private ?ICAPRequest $icapRequest;
	private string $service;
	private string $virusHeader;
	private int $chunkSize;
	private bool $tls;

	private bool $verifyTlsPeer = true;
	private ICertificateManager $certificateManager;
	private int $avIcapConnectionTimeout;

	public function __construct(
		AppConfig $config,
		LoggerInterface $logger,
		StatusFactory $statusFactory,
		ICertificateManager $certificateManager,
		bool $verifyTlsPeer = true,
	) {
		parent::__construct($config, $logger, $statusFactory);

		$this->service = $config->getAvIcapRequestService();
		$this->virusHeader = $config->getAvIcapResponseHeader();
		$this->chunkSize = (int)$config->getAvIcapChunkSize();
		$this->mode = $config->getAvIcapMode();
		$this->tls = $config->getAvIcapTls();
		$this->verifyTlsPeer = $verifyTlsPeer;
		$this->certificateManager = $certificateManager;
		$this->avIcapConnectionTimeout = (int)$config->getAvIcapConnectTimeout();

	}

	public function initScanner() {
		parent::initScanner();
		$this->writeHandle = fopen('php://temp', 'w+');
		if ($this->writeHandle === false) {
			throw new \RuntimeException('Failed to open temporary write handle.');
		}

		$avHost = $this->appConfig->getAvHost();
		$avPort = $this->appConfig->getAvPort();
		if (!($avHost && $avPort)) {
			throw new \RuntimeException('The ICAP port and host are not set up.');
		}
		if ($this->tls) {
			$this->icapClient = new ICAPTlsClient($avHost, (int)$avPort, $this->avIcapConnectionTimeout, $this->certificateManager, $this->verifyTlsPeer);
		} else {
			$this->icapClient = new ICAPClient($avHost, (int)$avPort, $this->avIcapConnectionTimeout);
		}

		$path = '/' . trim($this->path, '/');
		$remote = $this->request ? $this->request->getRemoteAddress() : null;
		$encodedPath = implode('/', array_map('rawurlencode', explode('/', $path)));

		try {
			if ($this->mode === ICAPClient::MODE_REQ_MOD) {
				$this->icapRequest = $this->icapClient->reqmod($this->service, [
					'Allow' => 204,
					'X-Client-IP' => $remote,
				], [
					"PUT $encodedPath HTTP/1.0",
					'Host: nextcloud'
				]);
			} else {
				$this->icapRequest = $this->icapClient->respmod($this->service, [
					'Allow' => 204,
					'X-Client-IP' => $remote,
				], [
					"GET $encodedPath HTTP/1.0",
					'Host: nextcloud',
				], [
					'HTTP/1.0 200 OK',
					'Content-Length: 1', // a dummy, non-zero, content length seems to be enough
				]);
			}
		} catch (\Throwable $e) {
			throw new \RuntimeException('Failed to initialize ICAP request: ' . $e->getMessage(), 0, $e);
		}
	}

	protected function writeChunk($chunk) {
		if (ftell($this->writeHandle) > $this->chunkSize) {
			$this->flushBuffer();
		}
		parent::writeChunk($chunk);
	}

	private function flushBuffer() {
		rewind($this->writeHandle);
		$data = stream_get_contents($this->writeHandle);
		$this->icapRequest->write($data);
		$this->writeHandle = fopen('php://temp', 'w+');
	}

	protected function scanBuffer() {
		$this->flushBuffer();
		$response = $this->icapRequest->finish();
		$code = $response->getStatus()->getCode();

		$this->status->setNumericStatus(Status::SCANRESULT_CLEAN);
		$icapHeaders = $response->getIcapHeaders();
		if ($code === 200 || $code === 204) {
			// c-icap/clamav reports this header
			$virus = $icapHeaders[$this->virusHeader] ?? false;
			if ($virus) {
				$this->status->setNumericStatus(Status::SCANRESULT_INFECTED);
				$this->status->setDetails($virus);
			}

			// kaspersky(pre 2020 product editions) and McAfee handling
			$respHeader = $response->getResponseHeaders()['HTTP_STATUS'] ?? '';
			if (\strpos($respHeader, '403 Forbidden') || \strpos($respHeader, '403 VirusFound')) {
				$this->status->setNumericStatus(Status::SCANRESULT_INFECTED);
			}
		} elseif ($code === 202) {
			$this->status->setNumericStatus(Status::SCANRESULT_UNCHECKED);
		} elseif ($code === 500 && isset($icapHeaders['X-Error-Code'])) {
			$uncheckableErrors = ['decode_error', 'max_archive_layers_exceeded', 'password_protected'];
			$blockedErrors = ['file_type_blocked', 'file_extension_blocked'];
			$icapErrorCode = $icapHeaders['X-Error-Code'];
			if (in_array($icapErrorCode, $uncheckableErrors)) {
				$this->status->setNumericStatus(Status::SCANRESULT_UNSCANNABLE);
			} elseif (in_array($icapErrorCode, $blockedErrors)) {
				$this->status->setNumericStatus(Status::SCANRESULT_INFECTED);
			} else {
				throw new \RuntimeException('Invalid response from ICAP server, got error code ' . $icapErrorCode);
			}
		} else {
			throw new \RuntimeException('Invalid response from ICAP server');
		}
	}

	protected function shutdownScanner() {
		$this->scanBuffer();
	}

	public function setDebugCallback(callable $callback): void {
		$this->icapClient->setDebugCallback($callback);
	}
}
