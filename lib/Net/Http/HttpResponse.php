<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Net\Http;

class HttpResponse {
	/**
	 * @param resource $body
	 */
	public function __construct(
		private readonly HttpResponseStatus $status,
		private readonly array $headers,
		private $body,
	) {
	}

	public function getStatus(): HttpResponseStatus {
		return $this->status;
	}

	public function getHeaders(): array {
		return $this->headers;
	}

	/**
	 * @return resource
	 */
	public function getBody() {
		return $this->body;
	}
}
