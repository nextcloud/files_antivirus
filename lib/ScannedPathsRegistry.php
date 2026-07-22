<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus;

/**
 * Request-scoped registry that tracks which file paths were successfully scanned
 * during this request. AvirWrapper writes results here; NodeWrittenListener reads
 * from here to decide whether to persist the "scanned" state to the database.
 */
class ScannedPathsRegistry {
	/** @var array<string, int> normalized path => scan result (Status::SCANRESULT_*) */
	private array $results = [];

	/**
	 * Record a scan result for a given absolute filesystem path.
	 * Only call this when the file is being accepted (i.e. not blocked).
	 */
	public function registerResult(string $path, int $status): void {
		$this->results[$this->normalizePath($path)] = $status;
	}

	/**
	 * Retrieve the scan result recorded for a path, or null if no scan was recorded.
	 */
	public function getResult(string $path): ?int {
		return $this->results[$this->normalizePath($path)] ?? null;
	}

	private function normalizePath(string $path): string {
		return '/' . trim($path, '/');
	}
}
