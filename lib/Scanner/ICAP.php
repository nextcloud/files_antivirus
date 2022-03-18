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
use OCA\Files_Antivirus\ICAP\ICAPClient;
use OCA\Files_Antivirus\Status;
use OCA\Files_Antivirus\StatusFactory;
use OCP\Http\Client\IClientService;
use OCP\ILogger;

class ICAP extends ScannerBase {
	private ICAPClient $icapClient;

	public function __construct(
		AppConfig $config,
		ILogger $logger,
		StatusFactory $statusFactory
	) {
		parent::__construct($config, $logger, $statusFactory);

		$avHost = $this->appConfig->getAvHost();
		$avPort = $this->appConfig->getAvPort();

		if (!($avHost && $avPort)) {
			throw new \RuntimeException('The ICAP port and host are not set up.');
		}
		$this->icapClient = new ICAPClient($avHost, (int)$avPort);
	}

	public function initScanner() {
		parent::initScanner();
		$this->writeHandle = fopen("php://temp", 'w+');
	}

	protected function scanBuffer() {
		rewind($this->writeHandle);

		$response = $this->icapClient->reqmod('req', [
			'req-hdr' => "PUT / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n",
			'req-body' => stream_get_contents($this->writeHandle)
		], [
			'Allow' => 204
		]);
		$code = (int)$response['protocol']['code'] ?? 500;

		$this->status->setNumericStatus(Status::SCANRESULT_CLEAN);
		if ($code === 200 || $code === 204) {
			// c-icap/clamav reports this header
			$virus = $response['headers']['X-Infection-Found'] ?? false;
			if ($virus) {
				$this->status->setNumericStatus(Status::SCANRESULT_INFECTED);
				$this->status->setDetails($virus);
			}

			// kaspersky(pre 2020 product editions) and McAfee handling
			$respHeader = $response['body']['res-hdr']['HTTP_STATUS'] ?? '';
			if (\strpos($respHeader, '403 Forbidden') || \strpos($respHeader, '403 VirusFound')) {
				$this->status->setNumericStatus(Status::SCANRESULT_INFECTED);
			}
		} else {
			throw new \RuntimeException('AV failed!');
		}
	}

	protected function shutdownScanner() {
		$this->scanBuffer();
	}
}
