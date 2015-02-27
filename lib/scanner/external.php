<?php
/**
 * Copyright (c) 2014 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */


namespace OCA\Files_Antivirus\Scanner;

use OCA\Files_Antivirus\Status;
use OCA\Files_Antivirus\Item;

class External extends \OCA\Files_Antivirus\Scanner {
	
	// Daemon/socket mode
	protected $useSocket;
	
	public function __construct($config){
		$this->appConfig = $config;
		$this->useSocket = $this->appConfig->getAvMode() === 'socket';
	}
	
	/**
	 * Scan a file
	 * @param Item $item - item to scan
	 * @return Status
	 * @throws \RuntimeException
	 */
	public function scan(Item $item) {
		$this->status = new Status();
		
		if ($this->useSocket){
			$av_socket = $this->appConfig->getAvSocket();
			$shandler = stream_socket_client('unix://' . $av_socket, $errno, $errstr, 5);
			if (!$shandler) {
				throw new \RuntimeException('Cannot connect to "' . $av_socket . '": ' . $errstr . ' (code ' . $errno . ')');
			}
		} else {
			$av_host = $this->appConfig->getAvHost();
			$av_port = $this->appConfig->getAvPort();
			$shandler = ($av_host && $av_port) ? @fsockopen($av_host, $av_port) : false;
			if (!$shandler) {
				throw new \RuntimeException('The clamav module is not configured for daemon mode.');
			}
		}

		// request scan from the daemon
		fwrite($shandler, "nINSTREAM\n");
		while (false !== $chunk = $item->fread()) {
			$chunk_len = pack('N', strlen($chunk));
			fwrite($shandler, $chunk_len.$chunk);
		}
		fwrite($shandler, pack('N', 0));
		$response = fgets($shandler);
		\OCP\Util::writeLog('files_antivirus', 'Response :: '.$response, \OCP\Util::DEBUG);
		fclose($shandler);
		
		$this->status->parseResponse($response);
		
		return $this->status;
	}
}
