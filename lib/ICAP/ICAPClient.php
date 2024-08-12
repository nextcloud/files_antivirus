<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2022 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\ICAP;

use RuntimeException;

class ICAPClient {
	public const MODE_REQ_MOD = 'reqmod';
	public const MODE_RESP_MOD = 'respmod';

	/** @var string */
	protected $host;
	/** @var int */
	protected $port;
	/** @var int */
	protected $connectTimeout;
	/**
	 * @var (callable(string): void)|null
	 */
	private $debugCallback = null;

	public function __construct(string $host, int $port, int $connectTimeout) {
		$this->host = $host;
		$this->port = $port;
		$this->connectTimeout = $connectTimeout;
	}

	/**
	 * @param callable(string): void $callback
	 * @return void
	 */
	public function setDebugCallback(callable $callback): void {
		$this->debugCallback = $callback;
	}

	/**
	 * Connect to ICAP server
	 *
	 * @return resource
	 */
	protected function connect() {
		$stream = @\stream_socket_client(
			"tcp://{$this->host}:{$this->port}",
			$errorCode,
			$errorMessage,
			$this->connectTimeout
		);
		
		if (!$stream) {
			throw new RuntimeException(
				"Cannot connect to \"tcp://{$this->host}:{$this->port}\": $errorMessage (code $errorCode)"
			);
		}

		socket_set_timeout($stream, 600);

		return $stream;
	}

	/**
	 * Send REQMOD request
	 *
	 * @param string $service ICAP service
	 * @param array $headers
	 * @param array $requestHeaders
	 * @return ICAPRequest Response array
	 */
	public function reqmod(string $service, array $headers, array $requestHeaders): ICAPRequest {
		$stream = $this->connect();
		return new ICAPRequest($stream, $this->host, $service, 'REQMOD', $headers, $requestHeaders, [], $this->debugCallback);
	}

	/**
	 * Send RESPMOD request
	 *
	 * @param string $service ICAP service
	 * @param array $headers
	 * @param array $requestHeaders
	 * @return ICAPRequest Response array
	 */
	public function respmod(string $service, array $headers, array $requestHeaders, array $responseHeaders): ICAPRequest {
		$stream = $this->connect();
		return new ICAPRequest($stream, $this->host, $service, 'RESPMOD', $headers, $requestHeaders, $responseHeaders, $this->debugCallback);
	}
}
