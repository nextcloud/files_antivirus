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

use RuntimeException;

class ICAPClient {
	private string $host;
	private int $port;
	private $socket;

	const USER_AGENT = 'NC-ICAP-CLIENT/0.5.0';

	/**
	 * Constructor
	 *
	 * @param string $host IP address of ICAP server
	 * @param int $port Port number
	 */
	public function __construct(string $host, int $port) {
		$this->host = $host;
		$this->port = $port;
	}

	/**
	 * Connect to ICAP server
	 *
	 * @return boolean True if successful
	 */
	private function connect(): bool {
		$this->socket = @\stream_socket_client(
			"tcp://{$this->host}:{$this->port}",
			$errorCode,
			$errorMessage,
			5
		);

		if (!$this->socket) {
			throw new \Exception(
				"Cannot connect to \"tcp://{$this->host}:{$this->port}\": $errorMessage (code $errorCode)"
			);
		}

		return true;
	}

	/**
	 * Close connection to ICAP server
	 */
	private function disconnect() {
		fclose($this->socket);
	}

	/**
	 * Get last error code from socket object
	 *
	 * @return int Socket error code
	 */
	public function getLastSocketError() {
		return socket_last_error($this->socket);
	}

	/**
	 * Generate request string
	 *
	 * @param string $method ICAP method
	 * @param string $service ICAP service
	 * @param array $body Request body data
	 * @param array $headers Array of headers
	 * @return string Request string
	 */
	public function getRequest(string $method, string $service, array $body = [], array $headers = []): string {
		if (!array_key_exists('Host', $headers)) {
			$headers['Host'] = $this->host;
		}

		if (!array_key_exists('User-Agent', $headers)) {
			$headers['User-Agent'] = self::USER_AGENT;
		}

		if (!array_key_exists('Connection', $headers)) {
			$headers['Connection'] = 'close';
		}

		$bodyData = '';
		$hasBody = false;
		$encapsulated = [];
		foreach ($body as $type => $data) {
			switch ($type) {
				case 'req-hdr':
				case 'res-hdr':
					$encapsulated[$type] = strlen($bodyData);
					$bodyData .= $data;
					break;

				case 'req-body':
				case 'res-body':
					$encapsulated[$type] = strlen($bodyData);
					$bodyData .= dechex(strlen($data)) . "\r\n";
					$bodyData .= $data;
					$bodyData .= "\r\n";
					$hasBody = true;
					break;
			}
		}

		if ($hasBody) {
			$bodyData .= "0\r\n\r\n";
		} elseif (count($encapsulated) > 0) {
			$encapsulated['null-body'] = strlen($bodyData);
		}

		if (count($encapsulated) > 0) {
			$headers['Encapsulated'] = '';
			foreach ($encapsulated as $section => $offset) {
				$headers['Encapsulated'] .= $headers['Encapsulated'] === '' ? '' : ', ';
				$headers['Encapsulated'] .= "{$section}={$offset}";
			}
		}

		$request = "{$method} icap://{$this->host}/{$service} ICAP/1.0\r\n";
		foreach ($headers as $header => $value) {
			$request .= "{$header}: {$value}\r\n";
		}

		$request .= "\r\n";
		$request .= $bodyData;

		return $request;
	}

	/**
	 * Send OPTIONS request
	 *
	 * @param string $service ICAP service
	 * @return array Response array
	 * @throws RuntimeException
	 */
	public function options(string $service): array {
		$request = $this->getRequest('OPTIONS', $service);
		return $this->send($request);
	}

	/**
	 * Send RESPMOD request
	 *
	 * @param string $service ICAP service
	 * @param array $body Request body data
	 * @return array Response array
	 * @throws RuntimeException
	 */
	public function respmod(string $service, array $body = [], array $headers = []): array {
		$request = $this->getRequest('RESPMOD', $service, $body, $headers);
		return $this->send($request);
	}

	/**
	 * Send REQMOD request
	 *
	 * @param string $service ICAP service
	 * @param array $body Request body data
	 * @return array Response array
	 * @throws RuntimeException
	 */
	public function reqmod(string $service, array $body = [], array $headers = []): array {
		$request = $this->getRequest('REQMOD', $service, $body, $headers);
		return $this->send($request);
	}

	/**
	 * Send request
	 *
	 * @param string $request Request string
	 * @return string Response string
	 * @throws RuntimeException
	 */
	private function send(string $request): array {
		$this->connect();
		if (@\fwrite($this->socket, $request) === false) {
			throw new \Exception(
				"Writing to \"{$this->host}:{$this->port}}\" failed"
			);
		}

		$headers = [];
		$resHdr = [];
		$protocol = $this->readIcapStatusLine();

		// McAfee seems to not properly close the socket once all response bytes are sent to the client
		// So if ICAP status is 204 we just stop reading
		if ($protocol['code'] !== 204) {
			$headers = $this->readHeaders();
			if (isset($headers['Encapsulated'])) {
				$resHdr = $this->parseResHdr($headers['Encapsulated']);
			}
		}

		$this->disconnect();
		return [
			'protocol' => $protocol,
			'headers' => $headers,
			'body' => ['res-hdr' => $resHdr]
		];
	}

	private function readIcapStatusLine(): array {
		$icapHeader = \trim(\fgets($this->socket));
		$numValues = \sscanf($icapHeader, "ICAP/%d.%d %d %s", $v1, $v2, $code, $status);
		if ($numValues !== 4) {
			throw new RuntimeException("Unknown ICAP response: \"$icapHeader\"");
		}
		return [
			'protocolVersion' => "$v1.$v2",
			'code' => $code,
			'status' => $status,
		];
	}

	private function parseResHdr(string $headerValue): array {
		$encapsulatedHeaders = [];
		$encapsulatedParts = \explode(",", $headerValue);
		foreach ($encapsulatedParts as $encapsulatedPart) {
			$pieces = \explode("=", \trim($encapsulatedPart));
			if ($pieces[1] === "0") {
				continue;
			}
			$rawEncapsulatedHeaders = \fread($this->socket, (int)$pieces[1]);
			$encapsulatedHeaders = $this->parseEncapsulatedHeaders($rawEncapsulatedHeaders);
			// According to the spec we have a single res-hdr part and are not interested in res-body content
			break;
		}
		return $encapsulatedHeaders;
	}

	private function readHeaders(): array {
		$headers = [];
		$prevString = "";
		while ($headerString = \fgets($this->socket)) {
			$trimmedHeaderString = \trim($headerString);
			if ($prevString === "" && $trimmedHeaderString === "") {
				break;
			}
			list($headerName, $headerValue) = $this->parseHeader($trimmedHeaderString);
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

	private function parseEncapsulatedHeaders(string $headerString) : array {
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
			list($name, $value) = $this->parseHeader($line);
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
