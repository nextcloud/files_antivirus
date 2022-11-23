<?php

declare(strict_types=1);

/**
 * @copyright Copyright (c) 2020 Robin Appelman <robin@icewind.nl>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

namespace OCA\Files_Antivirus\Scanner;

use OCA\Files_Antivirus\AppConfig;
use OCA\Files_Antivirus\Status;
use OCA\Files_Antivirus\StatusFactory;
use OCP\Http\Client\IClientService;
use Psr\Log\LoggerInterface;

class ExternalKaspersky extends ScannerBase {
	private IClientService $clientService;
	private int $chunkSize;

	public function __construct(
		AppConfig $config,
		LoggerInterface $logger,
		StatusFactory $statusFactory,
		IClientService $clientService
	) {
		parent::__construct($config, $logger, $statusFactory);
		$this->clientService = $clientService;
		$this->chunkSize = 10 * 1024 * 1024;
	}

	/**
	 * @return void
	 */
	public function initScanner() {
		parent::initScanner();

		$avHost = $this->appConfig->getAvHost();
		$avPort = $this->appConfig->getAvPort();

		if (!($avHost && $avPort)) {
			throw new \RuntimeException('The Kaspersky port and host are not set up.');
		}
		$this->writeHandle = fopen("php://temp", 'w+');
	}

	/**
	 * @return void
	 */
	protected function writeChunk($chunk) {
		if (ftell($this->writeHandle) > $this->chunkSize) {
			$this->scanBuffer();
			$this->writeHandle = fopen("php://temp", 'w+');
		}
		parent::writeChunk($chunk);
	}

	protected function scanBuffer(): void {
		rewind($this->writeHandle);

		$avHost = $this->appConfig->getAvHost();
		$avPort = $this->appConfig->getAvPort();

		$body = \stream_get_contents($this->writeHandle);
		$body = base64_encode($body);
		$response = $this->clientService->newClient()->post("$avHost:$avPort/api/v3.0/scanmemory", [
			'json' => [
				'timeout' => "60000",
				'object' => $body,
			],
			'connect_timeout' => 5,
		])->getBody();

		$this->logger->debug(
			'Response :: ' . $response,
			['app' => 'files_antivirus']
		);

		$response = json_decode($response, true);
		$scanResult = $response['scanResult'];

		if (substr($scanResult, 0, 5) === 'CLEAN' && $this->status->getNumericStatus() != Status::SCANRESULT_INFECTED) {
			$this->status->setNumericStatus(Status::SCANRESULT_CLEAN);
		} elseif (substr($scanResult, 0, 11) === 'NON_SCANNED' && $this->status->getNumericStatus() != Status::SCANRESULT_INFECTED) {
			if ($scanResult === 'NON_SCANNED (PASSWORD PROTECTED)') {
				// if we can't scan the file at all, there is no use in trying to scan it again later
				$this->status->setNumericStatus(Status::SCANRESULT_CLEAN);
			} else {
				$this->status->setNumericStatus(Status::SCANRESULT_UNCHECKED);
			}
			$this->status->setDetails($scanResult);
		} else {
			$this->status->setNumericStatus(Status::SCANRESULT_INFECTED);
			if (strpos($scanResult, "DETECT ") === 0) {
				$scanResult = substr($scanResult, 7);
			}
			if (isset($response['detectionName'])) {
				$scanResult .= ' ' . $response['detectionName'];
			}
			$this->status->setDetails($scanResult);
		}
	}

	/**
	 * @return void
	 */
	protected function shutdownScanner() {
		$this->scanBuffer();
	}
}
