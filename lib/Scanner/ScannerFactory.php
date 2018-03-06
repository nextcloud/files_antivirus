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

class ScannerFactory{
	
	/** @var AppConfig */
	protected $appConfig;
	
	/** @var ILogger */
	protected $logger;

	/** @var StatusFactory */
	protected $statusFactory;
	
	/** @var string */
	protected $scannerClass;
	
	public function __construct(AppConfig $appConfig, ILogger $logger, StatusFactory $statusFactory){
			$this->appConfig = $appConfig;
			$this->logger = $logger;
			$this->statusFactory = $statusFactory;

			try {
				$avMode = $appConfig->getAvMode();
				switch($avMode) {
					case 'daemon':
					case 'socket':
						$this->scannerClass = External::class;
						break;
					case 'executable':
						$this->scannerClass = Local::class;
						break;
					default:
						$this->logger->warning('Application is misconfigured. Please check the settings at the admin page. Invalid mode: ' . $avMode);
						break;
				}
			} catch (\Exception $e){
				$logger->logException($e);
			}
	}
	
	/**
	 * Produce a scanner instance 
	 * @return ScannerBase
	 */
	public function getScanner(){
		return new $this->scannerClass($this->appConfig, $this->logger, $this->statusFactory);
	}
}
