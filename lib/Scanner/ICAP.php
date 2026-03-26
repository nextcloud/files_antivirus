<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2020 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Scanner;

use OCA\Files_Antivirus\AppInfo\ConfigLexicon;
use OCA\Files_Antivirus\ICAP\ICAPClient;
use OCA\Files_Antivirus\ICAP\ICAPRequest;
use OCA\Files_Antivirus\ICAP\ICAPTlsClient;
use OCA\Files_Antivirus\Status;
use OCA\Files_Antivirus\StatusFactory;
use OCP\AppFramework\Services\IAppConfig;
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

	private int $avIcapConnectionTimeout;

	public function __construct(
		IAppConfig $appConfig,
		LoggerInterface $logger,
		StatusFactory $statusFactory,
		private readonly ICertificateManager $certificateManager,
		private readonly bool $verifyTlsPeer = true,
	) {
		parent::__construct($appConfig, $logger, $statusFactory);

		$this->service = $appConfig->getAppValueString(ConfigLexicon::AV_ICAP_REQUEST_SERVICE);
		$this->virusHeader = $appConfig->getAppValueString(ConfigLexicon::AV_ICAP_RESPONSE_HEADER);
		$this->chunkSize = $appConfig->getAppValueInt(ConfigLexicon::AV_ICAP_CHUNK_SIZE);
		$this->mode = $appConfig->getAppValueString(ConfigLexicon::AV_ICAP_MODE);
		$this->tls = $appConfig->getAppValueBool(ConfigLexicon::AV_ICAP_TLS);
		$this->avIcapConnectionTimeout = $appConfig->getAppValueInt(ConfigLexicon::AV_ICAP_CONNECT_TIMEOUT);

	}

	#[\Override]
	public function initScanner(): void {
		parent::initScanner();
		$this->writeHandle = fopen('php://temp', 'w+');
		if ($this->writeHandle === false) {
			throw new \RuntimeException('Failed to open temporary write handle.');
		}

		$avHost = $this->appConfig->getAppValueString(ConfigLexicon::AV_HOST);
		$avPort = $this->appConfig->getAppValueInt(ConfigLexicon::AV_PORT);
		if (!($avHost && $avPort)) {
			throw new \RuntimeException('The ICAP port and host are not set up.');
		}
		if ($this->tls) {
			$this->icapClient = new ICAPTlsClient($avHost, $avPort, $this->avIcapConnectionTimeout, $this->certificateManager, $this->verifyTlsPeer);
		} else {
			$this->icapClient = new ICAPClient($avHost, $avPort, $this->avIcapConnectionTimeout);
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

	#[\Override]
	protected function writeChunk(string $chunk): void {
		if (ftell($this->writeHandle) > $this->chunkSize) {
			$this->flushBuffer();
		}
		parent::writeChunk($chunk);
	}

	private function flushBuffer(): void {
		rewind($this->writeHandle);
		$data = stream_get_contents($this->writeHandle);
		$this->icapRequest->write($data);
		$this->writeHandle = fopen('php://temp', 'w+');
	}

	protected function scanBuffer(): void {
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

	#[\Override]
	protected function shutdownScanner(): void {
		$this->scanBuffer();
	}

	#[\Override]
	public function setDebugCallback(callable $callback): void {
		$this->icapClient->setDebugCallback($callback);
	}
}
