<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2022 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Net\Icap;

use OCA\Files_Antivirus\Net\Http\HttpResponse;
use OCA\Files_Antivirus\Net\Http\HttpResponseStatus;

class IcapResponse extends HttpResponse {
	public function __construct(
		HttpResponseStatus $status,
		array $headers,
		public readonly array $responseHeaders,
	) {
		parent::__construct($status, $headers, fopen('php://temp', 'r'));
	}

	public function getResponseHeaders(): array {
		return $this->responseHeaders;
	}
}
