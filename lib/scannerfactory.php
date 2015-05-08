<?php
/**
 * Copyright (c) 2014 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus;

use \OCP\ILogger;

class ScannerFactory{
	
	/**
	 * @var \OCA\Files_Antivirus\AppConfig
	 */
	protected $appConfig;
	
	/**
	 * @var ILogger;
	 */
	protected $logger;
	
	/**
	 * @var string
	 */
	protected $scannerClass;
	
	public function __construct(AppConfig $appConfig, ILogger $logger){
			$this->appConfig = $appConfig;
			$this->logger = $logger;
			try {
				$avMode = $appConfig->getAvMode();
				switch($avMode) {
					case 'daemon':
					case 'socket':
						$this->scannerClass = 'OCA\Files_Antivirus\Scanner\External';
						break;
					case 'executable':
						$this->scannerClass = 'OCA\Files_Antivirus\Scanner\Local';
						break;
					default:
						$this->logger->warning('Application is misconfigured. Please check the settings at the admin page. Invalid mode: ' . $avMode);
						break;
				}
			} catch (\Exception $e){
				$message = 	implode(' ', [ __CLASS__, __METHOD__, $e->getMessage()]);
				$logger->warning($message);
			}
	}
	
	/**
	 * Produce a scanner instance 
	 * @return \OCA\Files_Antivirus\Scanner
	 */
	public function getScanner(){
		return new $this->scannerClass($this->appConfig);
	}
}
