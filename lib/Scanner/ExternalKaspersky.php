<?php declare(strict_types=1);
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
use OCP\ILogger;

class ExternalKaspersky extends ScannerBase {
	/** @var IClientService IClientService */
	private $clientService;

	public function __construct(AppConfig $config, ILogger $logger, StatusFactory $statusFactory, IClientService $clientService) {
		parent::__construct($config, $logger, $statusFactory);
		$this->clientService = $clientService;
	}

	public function initScanner() {
		parent::initScanner();

		$avHost = $this->appConfig->getAvHost();
		$avPort = $this->appConfig->getAvPort();

		if (!($avHost && $avPort)) {
			throw new \RuntimeException('The Kaspersky port and host are not set up.');
		}
		$this->writeHandle = fopen("php://temp", 'w+');
	}

	protected function shutdownScanner() {
		rewind($this->writeHandle);

		$avHost = $this->appConfig->getAvHost();
		$avPort = $this->appConfig->getAvPort();

		$response = $this->clientService->newClient()->post("$avHost:$avPort/scanmemory", [
			'body' => $this->writeHandle,
			'headers' => [
				'X-KAV-Timeout' => '60000',
				'X-KAV-ProtocolVersion' => '1',
			],
		])->getBody();

		$this->logger->debug(
			'Response :: ' . $response,
			['app' => 'files_antivirus']
		);

		if (trim($response) === 'CLEAN') {
			$this->status->setNumericStatus(Status::SCANRESULT_CLEAN);
		} else {
			$this->status->setNumericStatus(Status::SCANRESULT_INFECTED);
			if (strpos($response, "DETECT ") === 0) {
				$response = substr($response, 7);
			}
			$this->status->setDetails($response);
		}
	}
}
