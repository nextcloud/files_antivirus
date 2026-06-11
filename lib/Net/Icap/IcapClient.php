<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2022 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Net\Icap;

use OCA\Files_Antivirus\Net\TcpClient;

class IcapClient {
	public const MODE_REQ_MOD = 'reqmod';
	public const MODE_RESP_MOD = 'respmod';

	/**
	 * @var (callable(string): void)|null
	 */
	private $debugCallback = null;

	public function __construct(
		private readonly TcpClient $transport,
	) {
	}

	/**
	 * @param callable(string): void $callback
	 * @return void
	 */
	public function setDebugCallback(callable $callback): void {
		$this->debugCallback = $callback;
	}

	/**
	 * Send REQMOD request
	 */
	public function reqmod(string $service, array $headers, array $requestHeaders): IcapRequest {
		$stream = $this->transport->connect();
		return new IcapRequest($stream, $this->transport->host, $service, 'REQMOD', $headers, $requestHeaders, [], $this->debugCallback);
	}

	/**
	 * Send RESPMOD request
	 */
	public function respmod(string $service, array $headers, array $requestHeaders, array $responseHeaders): IcapRequest {
		$stream = $this->transport->connect();
		return new IcapRequest($stream, $this->transport->host, $service, 'RESPMOD', $headers, $requestHeaders, $responseHeaders, $this->debugCallback);
	}
}
