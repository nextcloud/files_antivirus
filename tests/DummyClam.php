<?php
/**
 * Copyright (c) 2016 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_antivirus\Tests;

class DummyClam {
	const TEST_STREAM_SIZE = 524288; // 512K
	const TEST_SIGNATURE = 'does the job';
	private $chunkSize = 8192; // 8K
	private $socketDN;
	private $socket;

	public function __construct($socketPath){
		$this->socketDN = $socketPath;
	}

	public function startServer(){
		$this->socket = stream_socket_server($this->socketDN, $errNo, $errStr);
		if (!is_resource($this->socket)){
			throw new \Exception(
				sprintf(
					'Unable to open socket. Error code: %s. Error message: "%s"',
					$errNo,
					$errStr
				)
			);
		}
		// listen
		while (true){
			$connection = @stream_socket_accept($this->socket);
			if (is_resource($connection)){
				stream_set_blocking($connection, false);
				$this->handleConnection($connection);
				@fclose($connection);
			}
		}
	}
	protected function handleConnection($connection){
		$buffer = '';
		$isAborted = false;
		do {
			$chunk = fread($connection, $this->chunkSize);
			$nextBufferSize = strlen($buffer) + strlen($chunk);
			if ($nextBufferSize > self::TEST_STREAM_SIZE){
				$isAborted = true;
				break;
			}
			$buffer = $buffer . $chunk;
		} while (!$this->shouldCloseConnection($buffer));
		if (!$isAborted){
			//echo $buffer;
			$response = strpos($buffer, self::TEST_SIGNATURE) !== false
				? 'Ohoho: Criminal.Joboholic FOUND'
				: 'Scanned OK'
			;
			fwrite($connection, $response);
		}
	}
	protected function shouldCloseConnection($buffer){
		$needle = pack('N', 0);
		return substr($buffer,-strlen($needle)) == $needle;
	}
}
