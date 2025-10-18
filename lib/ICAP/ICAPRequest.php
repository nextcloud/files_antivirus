<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2022 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\ICAP;

class ICAPRequest {
	public const USER_AGENT = 'NC-ICAP-CLIENT/0.5.0';

	/** @var resource */
	public $stream;

	/**
	 * @var (callable(string): void)|null $responseCallback
	 */
	private $responseCallback;

	public function __construct(
		$stream,
		string $host,
		string $service,
		string $method,
		array $headers,
		array $requestHeaders,
		array $responseHeaders,
		?callable $responseCallback = null
	) {
		$this->stream = $stream;
		$this->responseCallback = $responseCallback;

		if (!array_key_exists('Host', $headers)) {
			$headers['Host'] = $host;
		}

		if (!array_key_exists('User-Agent', $headers)) {
			$headers['User-Agent'] = self::USER_AGENT;
		}

		if (!array_key_exists('Connection', $headers)) {
			$headers['Connection'] = 'close';
		}

		$requestHeadersLength = array_sum(array_map(function (string $header) {
			return strlen($header) + 2;
		}, $requestHeaders)) + 2;

		if ($responseHeaders) {
			$responseHeaderLength = array_sum(array_map(function (string $header) {
				return strlen($header) + 2;
			}, $responseHeaders)) + 2;
			$encapsulated = [
				'req-hdr' => 0,
				'res-hdr' => $requestHeadersLength,
				'res-body' => $requestHeadersLength + $responseHeaderLength,
			];
		} else {
			$encapsulated = [
				'req-hdr' => 0,
				'req-body' => $requestHeadersLength,
			];
		}

		$headers['Encapsulated'] = '';
		foreach ($encapsulated as $section => $offset) {
			$headers['Encapsulated'] .= $headers['Encapsulated'] === '' ? '' : ', ';
			$headers['Encapsulated'] .= "{$section}={$offset}";
		}

		$request = "{$method} icap://{$host}/{$service} ICAP/1.0\r\n";
		foreach ($headers as $header => $value) {
			$request .= "{$header}: {$value}\r\n";
		}

		$request .= "\r\n";
		foreach ($requestHeaders as $requestHeader) {
			$request .= "$requestHeader\r\n";
		}

		$request .= "\r\n";
		if ($responseHeaders) {
			foreach ($responseHeaders as $responseHeader) {
				$request .= "$responseHeader\r\n";
			}
			$request .= "\r\n";
		}

		if ($this->responseCallback) {
			($this->responseCallback)('ICAP Request headers:');
			($this->responseCallback)($request);
		}

		fwrite($this->stream, $request);
	}

	public function write(string $data): void {
		fwrite($this->stream, dechex(strlen($data)) . "\r\n" . $data . "\r\n");
	}

	public function finish(): IcapResponse {
		fwrite($this->stream, "0\r\n\r\n");

		$parser = new ResponseParser();
		if ($this->responseCallback) {
			$response = stream_get_contents($this->stream);

			($this->responseCallback)('ICAP Response:');
			($this->responseCallback)($response);
			$stream = fopen('php://temp', 'r+');
			fwrite($stream, $response);
			rewind($stream);
			return $parser->read_response($stream);
		} else {
			return $parser->read_response($this->stream);
		}
	}
}
