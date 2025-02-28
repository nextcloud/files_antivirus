<?php

/**
 * SPDX-FileCopyrightText: 2017-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2014-2016 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
namespace OCA\Files_Antivirus\Scanner;

use OCA\Files_Antivirus\AppConfig;
use OCP\IRequest;
use Psr\Container\ContainerInterface;

class ScannerFactory {
	protected AppConfig $appConfig;
	protected ContainerInterface $serverContainer;
	protected IRequest $request;

	public function __construct(
		AppConfig $appConfig,
		ContainerInterface $serverContainer,
		IRequest $request
	) {
		$this->appConfig = $appConfig;
		$this->serverContainer = $serverContainer;
		$this->request = $request;
	}

	/**
	 * Produce a scanner instance
	 *
	 * @return IScanner
	 */
	public function getScanner(?string $path) {
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
		$scanner = $this->serverContainer->get($scannerClass);
		if ($path !== null) {
			$scanner->setPath($path);
		}
		if ($this->request->getRemoteAddress()) {
			$scanner->setRequest($this->request);
		}
		return $scanner;
	}
}
