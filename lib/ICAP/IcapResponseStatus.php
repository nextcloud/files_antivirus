<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2022 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\ICAP;

class IcapResponseStatus {
	public function __construct(
		private readonly string $version,
		private readonly int $code,
		private readonly string $status
	) {
	}

	public function getVersion(): string {
		return $this->version;
	}

	public function getCode(): int {
		return $this->code;
	}

	public function getStatus(): string {
		return $this->status;
	}
}
