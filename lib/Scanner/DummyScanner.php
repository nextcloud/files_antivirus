<?php

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Scanner;

use OCA\Files_Antivirus\Item;
use OCA\Files_Antivirus\Status;
use OCA\Files_Antivirus\StatusFactory;
use OCP\IRequest;

/**
 * A dummy scanner that always returns "clean"
 */
class DummyScanner implements IScanner {
	public function __construct(
		private readonly StatusFactory $statusFactory,
	) {

	}

	#[\Override]
	public function getStatus(): Status {
		$status = $this->statusFactory->newStatus();
		$status->setNumericStatus(Status::SCANRESULT_CLEAN);
		return $status;
	}

	/**
	 * Synchronous scan
	 *
	 * @param Item $item
	 * @return Status
	 */
	#[\Override]
	public function scan(Item $item): Status {
		return $this->getStatus();
	}

	#[\Override]
	public function scanString(string $data): Status {
		return $this->getStatus();
	}

	#[\Override]
	public function onAsyncData(string $data): void {
		// noop
	}

	#[\Override]
	public function completeAsyncScan(): Status {
		return $this->getStatus();
	}

	#[\Override]
	public function initScanner(): void {
		// noop
	}

	#[\Override]
	public function setDebugCallback(callable $callback): void {
		// unsupported
	}

	public function setPath(string $path): void {
		// noop
	}

	public function setRequest(IRequest $request): void {
		// noop
	}
}
