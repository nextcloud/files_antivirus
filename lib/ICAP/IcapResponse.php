<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2022 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\ICAP;

class IcapResponse {
	/** @var IcapResponseStatus */
	private $status;
	/** @var array */
	private $headers;
	/** @var array */
	private $responseHeaders;

	public function __construct(
		IcapResponseStatus $status,
		array $headers,
		array $responseHeaders
	) {
		$this->status = $status;
		$this->headers = $headers;
		$this->responseHeaders = $responseHeaders;
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
