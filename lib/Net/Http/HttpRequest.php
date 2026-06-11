<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Net\Http;

class HttpRequest {
	public const USER_AGENT = 'NC-AV-CLIENT';

	/**
	 * @param resource $stream
	 */
	public function __construct(
		public $stream,
		public readonly string $host,
		public readonly string $method,
		public readonly string $path,
		public array $headers,
		public readonly string $protocol = 'HTTP/1.1',
	) {
		if (!array_key_exists('Host', $this->headers)) {
			$this->headers['Host'] = $host;
		}

		if (!array_key_exists('User-Agent', $this->headers)) {
			$this->headers['User-Agent'] = self::USER_AGENT;
		}

		if (!array_key_exists('Connection', $this->headers)) {
			$this->headers['Connection'] = 'close';
		}
	}

	protected function buildInitialRequest(): string {
		$request = "{$this->method} {$this->path} {$this->protocol}\r\n";
		foreach ($this->headers as $header => $value) {
			$request .= "{$header}: {$value}\r\n";
		}

		$request .= "\r\n";
		return $request;
	}

	/**
	 * Write the headers
	 */
	public function init(): void {
		fwrite($this->stream, $this->buildInitialRequest());
	}

	/**
	 * Write a chunk of data
	 */
	public function write(string $data): void {
		fwrite($this->stream, $data);
	}

	public function finish(): HttpResponse {
		$parser = new HttpResponseParser();
		return $parser->readResponse($this->stream);
	}
}
