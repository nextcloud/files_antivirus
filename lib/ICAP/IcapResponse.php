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
