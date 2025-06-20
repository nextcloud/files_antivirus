<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2017-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2014-2016 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
namespace OCA\Files_Antivirus\Scanner;

use OCA\Files_Antivirus\AppConfig;
use OCA\Files_Antivirus\Status;
use OCA\Files_Antivirus\StatusFactory;
use Psr\Log\LoggerInterface;

class ExternalClam extends ScannerBase {
	/**
	 * Daemon/socket mode
	 */
	private bool $useSocket;

	public function __construct(AppConfig $config, LoggerInterface $logger, StatusFactory $statusFactory) {
		parent::__construct($config, $logger, $statusFactory);
		$this->useSocket = $this->appConfig->getAvMode() === 'socket';
	}

	/**
	 * @return void
	 */
	public function initScanner() {
		parent::initScanner();

		if ($this->useSocket) {
			$avSocket = $this->appConfig->getAvSocket();
			if (str_starts_with($avSocket, 'tcp')) {
				$this->writeHandle = stream_socket_client($avSocket, $errno, $errstr, 5);
			} else {
				$this->writeHandle = stream_socket_client('unix://' . $avSocket, $errno, $errstr, 5);
			}
			if (!$this->getWriteHandle()) {
				throw new \RuntimeException('Cannot connect to "' . $avSocket . '": ' . $errstr . ' (code ' . $errno . ')');
			}
		} else {
			$avHost = $this->appConfig->getAvHost();
			$avPort = (int)$this->appConfig->getAvPort();
			if (!($avHost && $avPort)) {
				throw new \RuntimeException('The ClamAV port and host are not set up.');
			}
			$this->writeHandle = @fsockopen($avHost, $avPort);
			if (!$this->getWriteHandle()) {
				throw new \RuntimeException('Could not connect to ClamAV via ' . $avHost . ':' . $avPort . '. Please check that ClamAV is running and reachable.');
			}
		}

		// request scan from the daemon
		@fwrite($this->getWriteHandle(), "nINSTREAM\n");
	}

	/**
	 * @return void
	 */
	protected function shutdownScanner() {
		@fwrite($this->getWriteHandle(), pack('N', 0));
		$response = fgets($this->getWriteHandle());
		$this->logger->debug(
			'Response :: ' . $response,
			['app' => 'files_antivirus']
		);
		$handle = $this->getWriteHandle();

		$info = stream_get_meta_data($handle);
		@fclose($handle);

		if ($info['timed_out']) {
			$this->status->setNumericStatus(Status::SCANRESULT_UNCHECKED);
			$this->status->setDetails('Socket timed out while scanning');
		} elseif ($response === false) {
			$this->status->setNumericStatus(Status::SCANRESULT_UNCHECKED);
			$this->status->setDetails('Failed to read response from ClamAV');
		} else {
			$this->status->parseResponse($response);
		}
	}

	protected function prepareChunk($data) {
		$chunkLength = pack('N', strlen($data));
		return $chunkLength . $data;
	}
}
