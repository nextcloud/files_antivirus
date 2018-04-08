<?php
/**
 * Copyright (c) 2014 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */


namespace OCA\Files_Antivirus\Scanner;

use OCA\Files_Antivirus\AppConfig;
use OCA\Files_Antivirus\StatusFactory;
use OCP\ILogger;

class External extends ScannerBase {
	
	/**
	 * Daemon/socket mode
	 * @var bool
	 */
	private $useSocket;

	/**
	 * External constructor.
	 *
	 * @param AppConfig $config
	 * @param ILogger $logger
	 * @param StatusFactory $statusFactory
	 */
	public function __construct(AppConfig $config, ILogger $logger, StatusFactory $statusFactory) {
		parent::__construct($config, $logger, $statusFactory);
		$this->useSocket = $this->appConfig->getAvMode() === 'socket';
	}
	
	public function initScanner(){
		parent::initScanner();
		
		if ($this->useSocket){
			$avSocket = $this->appConfig->getAvSocket();
			$this->writeHandle = stream_socket_client('unix://' . $avSocket, $errno, $errstr, 5);
			if (!$this->getWriteHandle()) {
				throw new \RuntimeException('Cannot connect to "' . $avSocket . '": ' . $errstr . ' (code ' . $errno . ')');
			}
		} else {
			$avHost = $this->appConfig->getAvHost();
			$avPort = $this->appConfig->getAvPort();
			if (!($avHost && $avPort)) {
				throw new \RuntimeException('The ClamAV port and host are not set up.');
			}
			$this->writeHandle = ($avHost && $avPort) ? @fsockopen($avHost, $avPort) : false;
			if (!$this->getWriteHandle()) {
				throw new \RuntimeException('The ClamAV module is not in daemon mode.');
			}
		}

		// request scan from the daemon
		@fwrite($this->getWriteHandle(), "nINSTREAM\n");
	}
	
	protected function shutdownScanner(){
		@fwrite($this->getWriteHandle(), pack('N', 0));
		$response = fgets($this->getWriteHandle());
		$this->logger->debug(
			'Response :: ' . $response,
			['app' => 'files_antivirus']
		);
		@fclose($this->getWriteHandle());
		
		$this->status->parseResponse($response);
	}
	
	protected function prepareChunk($data){
		$chunkLength = pack('N', strlen($data));
		return $chunkLength . $data;
	}
}
