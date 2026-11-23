<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Net;

use RuntimeException;

class TcpClient {
	/** Seconds to wait for data from the server, this includes the time the server needs to scan the file */
	public const READ_TIMEOUT = 600;

	public function __construct(
		public readonly string $host,
		public readonly int $port,
		protected readonly int $connectTimeout,
	) {
	}

	/**
	 * Connect to TCP server
	 *
	 * @return resource
	 */
	public function connect() {
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

		stream_set_timeout($stream, self::READ_TIMEOUT);

		return $stream;
	}
}
