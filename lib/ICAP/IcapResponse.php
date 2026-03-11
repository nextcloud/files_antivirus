<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2022 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\ICAP;

class IcapResponse {
	public function __construct(
		private readonly IcapResponseStatus $status,
		private readonly array $headers,
		private readonly array $responseHeaders
	) {
	}

	public function getStatus(): IcapResponseStatus {
		return $this->status;
	}

	public function getIcapHeaders(): array {
		return $this->headers;
	}

	public function getResponseHeaders(): array {
		return $this->responseHeaders;
	}
}
