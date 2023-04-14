<?php

declare(strict_types=1);

/**
 * Copyright (c) 2014 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */


namespace OCA\Files_Antivirus\Scanner;

use OCA\Files_Antivirus\AppConfig;
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
			$this->writeHandle = stream_socket_client('unix://' . $avSocket, $errno, $errstr, 5);
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
				throw new \RuntimeException('The ClamAV module is not in daemon mode.');
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
		@fclose($handle);

		$this->status->parseResponse($response);
	}

	protected function prepareChunk($data) {
		$chunkLength = pack('N', strlen($data));
		return $chunkLength . $data;
	}
}
