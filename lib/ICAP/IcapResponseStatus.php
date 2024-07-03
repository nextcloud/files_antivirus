<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2022 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\ICAP;

class IcapResponseStatus {
	/** @var string */
	private $version;
	/** @var int */
	private $code;
	/** @var string */
	private $status;

	public function __construct(string $version, int $code, string $status) {
		$this->version = $version;
		$this->code = $code;
		$this->status = $status;
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
