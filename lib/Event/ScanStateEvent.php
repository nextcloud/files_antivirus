<?php
/**
 * SPDX-FileCopyrightText: 2018 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Event;

use OCP\EventDispatcher\Event;

class ScanStateEvent extends Event {
	/** @var bool */
	private $state;

	public function __construct(bool $state) {
		parent::__construct();
		$this->state = $state;
	}

	public function getState(): bool {
		return $this->state;
	}
}
