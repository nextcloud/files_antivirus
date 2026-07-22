<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Net;

use OCP\ICertificateManager;
use RuntimeException;

class TlsClient extends TcpClient {
	public function __construct(
		string $host,
		int $port,
		int $connectTimeout,
		private readonly ICertificateManager $certificateManager,
		private readonly bool $verifyTlsPeer = true,
	) {
		parent::__construct($host, $port, $connectTimeout);
	}

	/**
	 * Connect to TLS server
	 *
	 * @return resource
	 */
	#[\Override]
	public function connect() {
		$ctx = stream_context_create([
			'ssl' => [
				'verify_peer' => $this->verifyTlsPeer,
				'verify_peer_name' => $this->verifyTlsPeer,
				'allow_self_signed' => !$this->verifyTlsPeer,
				'cafile' => $this->certificateManager->getAbsoluteBundlePath()
			],
		]);
		$stream = \stream_socket_client(
			"tls://{$this->host}:{$this->port}",
			$errorCode,
			$errorMessage,
			$this->connectTimeout,
			STREAM_CLIENT_CONNECT,
			$ctx
		);

		if (!$stream) {
			throw new RuntimeException(
				"Cannot connect to \"tls://{$this->host}:{$this->port}\": $errorMessage (code $errorCode)"
			);
		}

		return $stream;
	}
}
