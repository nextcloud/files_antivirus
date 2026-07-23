<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Net\Http;

class HttpChunkedRequest extends HttpRequest {
	public function __construct(
		$stream,
		string $host,
		string $method,
		string $path,
		array $headers,
		string $protocol = 'HTTP/1.1',
	) {
		$headers['Transfer-Encoding'] = 'chunked';
		parent::__construct($stream, $host, $method, $path, $headers, $protocol);
	}

	#[\Override]
	public function write(string $data): void {
		parent::write(dechex(strlen($data)) . "\r\n" . $data . "\r\n");
	}

	#[\Override]
	public function finish(): HttpResponse {
		fwrite($this->stream, "0\r\n\r\n");
		return parent::finish();
	}
}
