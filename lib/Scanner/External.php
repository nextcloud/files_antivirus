<?php
/**
 * Copyright (c) 2014 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */


namespace OCA\Files_Antivirus\Scanner;

class External extends \OCA\Files_Antivirus\Scanner {
	
	// Daemon/socket mode
	private $useSocket;
	
	/**
	 * Handle to write data into
	 * @var resource 
	 */
	private $writeHandle;
	
	public function __construct($config){
		$this->appConfig = $config;
		$this->useSocket = $this->appConfig->getAvMode() === 'socket';
	}
	
	protected function initScanner(){
		parent::initScanner();
		
		if ($this->useSocket){
			$avSocket = $this->appConfig->getAvSocket();
			$this->writeHandle = stream_socket_client('unix://' . $avSocket, $errno, $errstr, 5);
			if (!$this->writeHandle) {
				throw new \RuntimeException('Cannot connect to "' . $avSocket . '": ' . $errstr . ' (code ' . $errno . ')');
			}
		} else {
			$avHost = $this->appConfig->getAvHost();
			$avPort = $this->appConfig->getAvPort();
			$this->writeHandle = ($avHost && $avPort) ? @fsockopen($avHost, $avPort) : false;
			if (!$this->writeHandle) {
				throw new \RuntimeException('The clamav module is not configured for daemon mode.');
			}
		}

		// request scan from the daemon
		fwrite($this->writeHandle, "nINSTREAM\n");
	}
	
	protected function shutdownScanner(){
		fwrite($this->writeHandle, pack('N', 0));
		$response = fgets($this->writeHandle);
		\OCP\Util::writeLog('files_antivirus', 'Response :: '.$response, \OCP\Util::DEBUG);
		fclose($this->writeHandle);
		
		$this->status->parseResponse($response);
	}
	
	protected function getWriteHandle(){
		return $this->writeHandle;
	}
	
	protected function prepareChunk($data){
		$chunk_len = pack('N', strlen($data));
		return $chunk_len.$data;
	}
}
