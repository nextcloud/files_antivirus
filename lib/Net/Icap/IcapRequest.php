<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2022 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Net\Icap;

use OCA\Files_Antivirus\Net\Http\HttpChunkedRequest;

class IcapRequest extends HttpChunkedRequest {
	public const USER_AGENT = 'NC-ICAP-CLIENT';

	/**
	 * @var (callable(string): void)|null $debugCallback
	 */
	private $debugCallback;

	public function __construct(
		$stream,
		string $host,
		string $service,
		string $method,
		array $headers,
		private readonly array $requestHeaders,
		private readonly array $responseHeaders,
		?callable $responseCallback = null,
	) {
		$requestHeadersLength = array_sum(array_map(function (string $header) {
			return strlen($header) + 2;
		}, $this->requestHeaders)) + 2;

		$encapsulated = [
			'req-hdr' => 0,
			'req-body' => $requestHeadersLength,
		];
		if ($this->responseHeaders) {
			$responseHeaderLength = array_sum(array_map(function (string $header) {
				return strlen($header) + 2;
			}, $this->responseHeaders)) + 2;
			$encapsulated[] = [
				'res-body' => $requestHeadersLength + $responseHeaderLength,
			];
		}

		$encapsulatedParts = array_map(fn ($section, $offset) => "{$section}={$offset}", array_keys($encapsulated), $encapsulated);
		$headers['Encapsulated'] = implode(', ', $encapsulatedParts);

		parent::__construct($stream, $host, $method, "icap://{$host}/{$service}", $headers, 'ICAP/1.0');

		$this->debugCallback = $responseCallback;
	}

	#[\Override]
	protected function buildInitialRequest(): string {
		$request = parent::buildInitialRequest();

		foreach ($this->requestHeaders as $requestHeader) {
			$request .= "$requestHeader\r\n";
		}

		$request .= "\r\n";
		if ($this->responseHeaders) {
			foreach ($this->responseHeaders as $responseHeader) {
				$request .= "$responseHeader\r\n";
			}
			$request .= "\r\n";
		}

		if ($this->debugCallback) {
			($this->debugCallback)('ICAP Request headers:');
			($this->debugCallback)($request);
		}

		return $request;
	}

	#[\Override]
	public function finish(): IcapResponse {
		fwrite($this->stream, "0\r\n\r\n");

		$parser = new IcapResponseParser();
		if ($this->debugCallback) {
			$response = stream_get_contents($this->stream);

			($this->debugCallback)('ICAP Response:');
			($this->debugCallback)($response);
			$stream = fopen('php://temp', 'r+');
			fwrite($stream, $response);
			rewind($stream);
			return $parser->readResponse($stream);
		} else {
			return $parser->readResponse($this->stream);
		}
	}
}
