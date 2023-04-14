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

class ICAPRequest {
	public const USER_AGENT = 'NC-ICAP-CLIENT/0.5.0';

	/** @var resource */
	public $stream;

	public function __construct(
		$stream,
		string $host,
		string $service,
		string $method,
		array $headers,
		array $requestHeaders,
		array $responseHeaders
	) {
		$this->stream = $stream;

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

		fwrite($this->stream, $request);
	}

	public function write(string $data): void {
		fwrite($this->stream, dechex(strlen($data)) . "\r\n" . $data . "\r\n");
	}

	public function finish(): IcapResponse {
		fwrite($this->stream, "0\r\n\r\n");
		return (new ResponseParser())->read_response($this->stream);
	}
}
