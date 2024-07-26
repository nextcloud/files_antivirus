<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2023 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Event;

use OCP\EventDispatcher\Event;
use OCP\Files\File;

class BeforeBackgroundScanEvent extends Event {
	private File $file;

	public function __construct(File $file) {
		$this->file = $file;
	}

	public function getFile(): File {
		return $this->file;
	}
}
