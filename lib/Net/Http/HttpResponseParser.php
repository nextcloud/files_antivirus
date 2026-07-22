<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Net\Http;

use RuntimeException;

class HttpResponseParser {
	/**
	 * @param resource $stream
	 */
	public function readResponse($stream): HttpResponse {
		$status = $this->readStatusLine($stream);
		$headers = $this->readHeaders($stream);

		return new HttpResponse($status, $headers, $stream);
	}

	protected function statusFormat(): string {
		return 'HTTP/%d.%d %d %s';
	}

	/**
	 * @param resource $stream
	 * @return HttpResponseStatus
	 */
	protected function readStatusLine($stream): HttpResponseStatus {
		$rawHeader = \fgets($stream);
		if ($rawHeader === false) {
			throw new RuntimeException('Error reading response from server');
		}
		$httpHeader = \trim($rawHeader);
		$numValues = \sscanf($httpHeader, $this->statusFormat(), $v1, $v2, $code, $status);
		if ($numValues !== 4) {
			throw new RuntimeException("Unknown response: \"$httpHeader\"");
		}
		return new HttpResponseStatus("$v1.$v2", (int)$code, $status);
	}

	protected function readHeaders($stream): array {
		$headers = [];
		while (($headerString = \fgets($stream)) !== false) {
			$trimmedHeaderString = \trim($headerString);
			if ($trimmedHeaderString === '') {
				break;
			}
			$header = $this->parseHeader($trimmedHeaderString);
			if ($header) {
				$headers[$header['name']] = $header['value'];
			}
		}
		return $headers;
	}

	protected function parseHeader(string $headerString): ?array {
		$parts = \preg_split('/:\ /', $headerString, 2);
		if (isset($parts[0])) {
			return ['name' => $parts[0], 'value' => $parts[1] ?? ''];
		} else {
			return null;
		}
	}
}
