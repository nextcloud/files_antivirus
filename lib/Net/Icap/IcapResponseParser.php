<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2022 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Net\Icap;

use OCA\Files_Antivirus\Net\Http\HttpResponseParser;

class IcapResponseParser extends HttpResponseParser {
	/**
	 * @param resource $stream
	 * @return IcapResponse
	 */
	#[\Override]
	public function readResponse($stream): IcapResponse {
		$headers = [];
		$resHdr = [];
		$status = $this->readStatusLine($stream);

		// McAfee seems to not properly close the socket once all response bytes are sent to the client
		// So if ICAP status is 204 we just stop reading
		if ($status->getCode() !== 204) {
			$headers = $this->readHeaders($stream);
			if (isset($headers['Encapsulated'])) {
				$resHdr = $this->readEncapsulated($stream, $headers['Encapsulated']);
			}
		}

		fclose($stream);
		return new IcapResponse($status, $headers, $resHdr);
	}

	#[\Override]
	protected function statusFormat(): string {
		return 'ICAP/%d.%d %d %s';
	}

	private function parseEncapsulatedHeader(string $headerValue): array {
		$result = [];
		$encapsulatedParts = \explode(',', $headerValue);
		foreach ($encapsulatedParts as $encapsulatedPart) {
			$pieces = \explode('=', \trim($encapsulatedPart));
			$result[$pieces[0]] = (int)$pieces[1];
		}
		return $result;
	}

	private function readEncapsulated($stream, string $headerValue): array {
		$encapsulated = $this->parseEncapsulatedHeader($headerValue);
		if (isset($encapsulated['res-hdr'])) {
			if ($encapsulated['res-hdr'] > 0) {
				fseek($stream, $encapsulated['res-hdr'], SEEK_CUR);
			}
		} elseif (isset($encapsulated['req-hdr'])) {
			if ($encapsulated['req-hdr'] > 0) {
				fseek($stream, $encapsulated['req-hdr'], SEEK_CUR);
			}
		} else {
			return [];
		}

		$status = trim(\fgets($stream));
		$encapsulatedHeaders = $this->readHeaders($stream);
		$encapsulatedHeaders['HTTP_STATUS'] = $status;

		return $encapsulatedHeaders;
	}
}
