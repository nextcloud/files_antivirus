<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2017-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2014-2016 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
namespace OCA\Files_Antivirus\Scanner;

use OCA\Files_Antivirus\AppConfig;
use OCA\Files_Antivirus\StatusFactory;
use Psr\Log\LoggerInterface;

class LocalClam extends ScannerBase {
	protected string $avPath;

	/**
	 * STDIN and STDOUT descriptors
	 * @var array of resources
	 */
	private array $pipes = [];

	/**
	 * Process handle
	 * @var resource
	 */
	private $process;

	public function __construct(AppConfig $config, LoggerInterface $logger, StatusFactory $statusFactory) {
		parent::__construct($config, $logger, $statusFactory);

		// get the path to the executable
		$this->avPath = escapeshellcmd($this->appConfig->getAvPath());

		// check that the executable is available
		if (!file_exists($this->avPath)) {
			throw new \RuntimeException('The antivirus executable could not be found at ' . $this->avPath);
		}
	}
	
	/**
	 * @return void
	 */
	public function initScanner() {
		parent::initScanner();
		
		// using 2>&1 to grab the full command-line output.
		$cmd = $this->avPath . ' ' . $this->appConfig->getCmdline() . ' - 2>&1';
		$descriptorSpec = [
			0 => ['pipe', 'r'], // STDIN
			1 => ['pipe', 'w']  // STDOUT
		];
		
		$this->process = proc_open($cmd, $descriptorSpec, $this->pipes);
		if (!is_resource($this->process)) {
			throw new \RuntimeException('Error starting process');
		}
		$this->writeHandle = $this->pipes[0];
	}
	
	/**
	 * @return void
	 */
	protected function shutdownScanner() {
		@fclose($this->pipes[0]);
		$output = stream_get_contents($this->pipes[1]);
		@fclose($this->pipes[1]);
		
		$result = proc_close($this->process);
		$this->logger->debug(
			'Exit code :: ' . $result . ' Response :: ' . $output,
			['app' => 'files_antivirus']
		);
		$this->status->parseResponse($output, $result);
	}
}
