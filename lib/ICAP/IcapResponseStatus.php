<?php

declare(strict_types=1);
/**
 * @copyright Copyright (c) 2022 Robin Appelman <robin@icewind.nl>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
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
