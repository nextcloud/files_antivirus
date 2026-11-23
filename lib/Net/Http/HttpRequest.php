<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Net\Http;

class HttpRequest {
	public const USER_AGENT = 'NC-AV-CLIENT';

	private int $bodyBytesSent = 0;
	private ?string $writeError = null;

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
		$this->send($this->buildInitialRequest());
	}

	/**
	 * Write a chunk of data
	 */
	public function write(string $data): void {
		$this->bodyBytesSent += $this->send($data);
	}

	/**
	 * Once a write failed, further data is discarded, the server might still have sent a response explaining why
	 *
	 * @return int the number of bytes sent
	 */
	private function send(string $data): int {
		if ($this->writeError !== null) {
			return 0;
		}

		$length = strlen($data);
		$sent = 0;
		while ($sent < $length) {
			error_clear_last();
			$written = @fwrite($this->stream, $sent === 0 ? $data : substr($data, $sent));
			if ($written === false || $written === 0) {
				$this->writeError = error_get_last()['message'] ?? 'Failed to write to the server';
				break;
			}
			$sent += $written;
		}
		return $sent;
	}

	public function getBodyBytesSent(): int {
		return $this->bodyBytesSent;
	}

	public function getWriteError(): ?string {
		return $this->writeError;
	}

	public function finish(): HttpResponse {
		$parser = new HttpResponseParser();
		return $parser->readResponse($this->stream);
	}
}
