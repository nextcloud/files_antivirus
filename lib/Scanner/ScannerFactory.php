<?php
/**
 * Copyright (c) 2014 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\Scanner;

use OCA\Files_Antivirus\AppConfig;
use OCP\IServerContainer;

class ScannerFactory {
	protected $appConfig;
	private $serverContainer;

	public function __construct(AppConfig $appConfig, IServerContainer $serverContainer) {
		$this->appConfig = $appConfig;
		$this->serverContainer = $serverContainer;
	}

	/**
	 * Produce a scanner instance
	 *
	 * @return IScanner
	 */
	public function getScanner(string $path) {
		$avMode = $this->appConfig->getAvMode();
		switch ($avMode) {
			case 'daemon':
			case 'socket':
				$scannerClass = ExternalClam::class;
				break;
			case 'executable':
				$scannerClass = LocalClam::class;
				break;
			case 'kaspersky':
				$scannerClass = ExternalKaspersky::class;
				break;
			case 'icap':
				$scannerClass = ICAP::class;
				break;
			default:
				throw new \InvalidArgumentException('Application is misconfigured. Please check the settings at the admin page. Invalid mode: ' . $avMode);
		}

		/** @var ScannerBase $scanner */
		$scanner = $this->serverContainer->resolve($scannerClass);
		$scanner->setPath($path);
		return $scanner;
	}
}
