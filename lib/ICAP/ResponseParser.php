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

use \RuntimeException;

class ResponseParser {
	/**
	 * @param resource $stream
	 * @return IcapResponse
	 */
	public function read_response($stream): IcapResponse {
		$headers = [];
		$resHdr = [];
		$status = $this->readIcapStatusLine($stream);

		// McAfee seems to not properly close the socket once all response bytes are sent to the client
		// So if ICAP status is 204 we just stop reading
		if ($status->getCode() !== 204) {
			$headers = $this->readHeaders($stream);
			if (isset($headers['Encapsulated'])) {
				$resHdr = $this->parseResHdr($stream, $headers['Encapsulated']);
			}
		}

		fclose($stream);
		return new IcapResponse($status, $headers, $resHdr);
	}

	/**
	 * @param resource $stream
	 * @return IcapResponseStatus
	 */
	private function readIcapStatusLine($stream): IcapResponseStatus {
		$icapHeader = \trim(\fgets($stream));
		$numValues = \sscanf($icapHeader, "ICAP/%d.%d %d %s", $v1, $v2, $code, $status);
		if ($numValues !== 4) {
			throw new RuntimeException("Unknown ICAP response: \"$icapHeader\"");
		}
		return new IcapResponseStatus("$v1.$v2", (int)$code, $status);
	}

	private function parseResHdr($stream, string $headerValue): array {
		$encapsulatedHeaders = [];
		$encapsulatedParts = \explode(",", $headerValue);
		foreach ($encapsulatedParts as $encapsulatedPart) {
			$pieces = \explode("=", \trim($encapsulatedPart));
			if ($pieces[1] === "0") {
				continue;
			}
			$rawEncapsulatedHeaders = \fread($stream, (int)$pieces[1]);
			$encapsulatedHeaders = $this->parseEncapsulatedHeaders($rawEncapsulatedHeaders);
			// According to the spec we have a single res-hdr part and are not interested in res-body content
			break;
		}
		return $encapsulatedHeaders;
	}

	private function readHeaders($stream): array {
		$headers = [];
		$prevString = "";
		while (($headerString = \fgets($stream)) !== false) {
			$trimmedHeaderString = \trim($headerString);
			if ($prevString === "" && $trimmedHeaderString === "") {
				break;
			}
			[$headerName, $headerValue] = $this->parseHeader($trimmedHeaderString);
			if ($headerName !== '') {
				$headers[$headerName] = $headerValue;
				if ($headerName == "Encapsulated") {
					break;
				}
			}
			$prevString = $trimmedHeaderString;
		}
		return $headers;
	}

	private function parseEncapsulatedHeaders(string $headerString): array {
		$headers = [];
		$split = \preg_split('/\r?\n/', \trim($headerString));
		$statusLine = \array_shift($split);
		if ($statusLine !== null) {
			$headers['HTTP_STATUS'] = $statusLine;
		}
		foreach (\preg_split('/\r?\n/', $headerString) as $line) {
			if ($line === '') {
				continue;
			}
			[$name, $value] = $this->parseHeader($line);
			if ($name !== '') {
				$headers[$name] = $value;
			}
		}

		return $headers;
	}

	private function parseHeader(string $headerString): array {
		$name = '';
		$value = '';
		$parts = \preg_split('/:\ /', $headerString, 2);
		if (isset($parts[0])) {
			$name = $parts[0];
			$value = $parts[1] ?? '';
		}
		return [$name, $value];
	}
}
