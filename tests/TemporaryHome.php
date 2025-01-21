<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2024 Robin Appelman <robin@icewind.nl>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests;

class TemporaryHome extends \OC\Files\Storage\Temporary {
	private string $id;

	public function __construct($arguments = []) {
		parent::__construct($arguments);
		$this->id = uniqid();
	}

	public function getId(): string {
		return 'home::' . $this->id;
	}

}
