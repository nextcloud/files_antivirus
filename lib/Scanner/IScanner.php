<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2020 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Scanner;

use OCA\Files_Antivirus\Item;
use OCA\Files_Antivirus\Status;

interface IScanner {
	/**
	 * @param callable(string): void $callback
	 */
	public function setDebugCallback(callable $callback): void;

	public function getStatus();

	/**
	 * Synchronous scan
	 *
	 * @param Item $item
	 * @return Status
	 */
	public function scan(Item $item): Status;

	/**
	 * Async scan - new portion of data is available
	 *
	 * @param string $data
	 */
	public function onAsyncData($data);

	/**
	 * Async scan - resource is closed
	 *
	 * @return Status
	 */
	public function completeAsyncScan(): Status;

	/**
	 * Open write handle. etc
	 */
	public function initScanner();

	/**
	 * Scan a chunk of data synchronously
	 *
	 * @param string $data
	 * @return Status
	 */
	public function scanString(string $data): Status;
}
