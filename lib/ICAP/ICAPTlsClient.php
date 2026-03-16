<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2022 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\ICAP;

use OCP\ICertificateManager;
use RuntimeException;

class ICAPTlsClient extends ICAPClient {
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
	 * Connect to ICAP server
	 *
	 * @return resource
	 */
	#[\Override]
	protected function connect() {
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
