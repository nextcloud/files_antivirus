<?php

namespace OCA\Files_Antivirus;

use Icewind\Streams\CallbackWrapper;
use Icewind\Streams\Wrapper;

class CallbackReadDataWrapper extends CallbackWrapper {
	/**
	 * @var callable
	 */
	protected $readDataCallback;

	/**
	 * Wraps a stream with the provided callbacks
	 *
	 * @param resource $source
	 * @param callable $read (optional)
	 * @param callable $write (optional)
	 * @param callable $close (optional)
	 * @param callable $readDir (optional)
	 * @return resource|bool
	 *
	 * @throws \BadMethodCallException
	 */
	public static function wrap($source, $read = null, $write = null, $close = null, $readDir = null, $preClose = null) {
		$context = stream_context_create([
			'callbackReadData' => [
				'source' => $source,
				'readData' => $read,
				'write' => $write,
				'close' => $close,
				'readDir' => $readDir,
				'preClose' => $preClose
			]
		]);
		return Wrapper::wrapSource($source, $context, 'callbackReadData', self::class);
	}

	/**
	 * @return true
	 */
	protected function open() {
		$context = $this->loadContext('callbackReadData');

		$this->readDataCallback = $context['readData'];
		$this->writeCallback = $context['write'];
		$this->closeCallback = $context['close'];
		$this->readDirCallBack = $context['readDir'];
		return true;
	}

	public function stream_read($count) {
		$result = parent::stream_read($count);
		if (is_callable($this->readDataCallback)) {
			call_user_func($this->readDataCallback, strlen($result), $result);
		}
		return $result;
	}
}
