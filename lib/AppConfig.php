<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus;

use OCA\Files_Antivirus\ICAP\ICAPClient;
use OCP\IConfig;

/**
 * @method ?string getAvMode()
 * @method ?string getAvSocket()
 * @method ?string getAvHost()
 * @method ?string getAvPort()
 * @method ?string getAvCmdOptions()
 * @method ?string getAvPath()
 * @method ?string getAvInfectedAction()
 * @method ?string getAvStreamMaxLength()
 * @method string getAvIcapMode()
 * @method ?string getAvIcapRequestService()
 * @method ?string getAvIcapResponseHeader()
 * @method ?string getAvIcapChunkSize()
 * @method ?string getAvIcapConnectTimeout()
 * @method null setAvMode(string $avMode)
 * @method null setAvSocket(string $avsocket)
 * @method null setAvHost(string $avHost)
 * @method null setAvPort(int $avPort)
 * @method null setAvMaxFileSize(int $fileSize)
 * @method null setAvScanFirstBytes(int $fileSize)
 * @method null setAvCmdOptions(string $avCmdOptions)
 * @method null setAvChunkSize(int $chunkSize)
 * @method null setAvPath(string $avPath)
 * @method null setAvInfectedAction(string $avInfectedAction)
 * @method null setAvIcapScanBackground(string $scanBackground)
 * @method null setAvIcapMode(string $mode)
 * @method null setAvIcapRequestService($reqService)
 * @method null setAvIcapResponseHeader($respHeader)
 * @method null setAvStreamMaxLength(int $length)
 */
class AppConfig {
	/** @var string */
	private $appName = 'files_antivirus';

	/** @var IConfig */
	private $config;

	private $defaults = [
		'av_mode' => 'executable',
		'av_socket' => '/var/run/clamav/clamd.ctl',
		'av_host' => '',
		'av_port' => '',
		'av_cmd_options' => '',
		'av_path' => '/usr/bin/clamscan',
		'av_max_file_size' => -1,
		'av_stream_max_length' => '26214400',
		'av_infected_action' => 'only_log',
		'av_background_scan' => 'on',
		'av_icap_mode' => ICAPClient::MODE_REQ_MOD,
		'av_icap_request_service' => 'avscan',
		'av_icap_response_header' => 'X-Infection-Found',
		'av_icap_chunk_size' => '1048576',
		'av_icap_connect_timeout' => '5',
		'av_scan_first_bytes' => -1,
	];

	/**
	 * AppConfig constructor.
	 *
	 * @param IConfig $config
	 */
	public function __construct(IConfig $config) {
		$this->config = $config;
	}

	public function getAvChunkSize(): int {
		// See http://php.net/manual/en/function.stream-wrapper-register.php#74765
		// and \OC_Helper::streamCopy
		return 8192;
	}

	public function getAvMaxFileSize(): int {
		return (int)$this->getAppValue('av_max_file_size');
	}

	/**
	 * Get full commandline
	 *
	 * @return string
	 */
	public function getCmdline(): string {
		$avCmdOptions = $this->getAvCmdOptions();

		$shellArgs = [];
		if ($avCmdOptions) {
			$shellArgs = explode(',', $avCmdOptions);
			$shellArgs = array_map(function ($i) {
				return escapeshellarg($i);
			},
				$shellArgs
			);
		}

		$preparedArgs = '';
		if (count($shellArgs)) {
			$preparedArgs = implode(' ', $shellArgs);
		}
		return $preparedArgs;
	}

	/**
	 * Get all setting values as an array
	 *
	 * @return array
	 */
	public function getAllValues(): array {
		$keys = array_keys($this->defaults);
		$values = array_map([$this, 'getAppValue'], $keys);
		$preparedKeys = array_map([$this, 'camelCase'], $keys);
		return array_combine($preparedKeys, $values);
	}

	/**
	 * Get a value by key
	 *
	 * @param string $key
	 * @return ?string
	 */
	public function getAppValue(string $key): ?string {
		$defaultValue = null;
		if (array_key_exists($key, $this->defaults)) {
			$defaultValue = $this->defaults[$key];
		}
		return $this->config->getAppValue($this->appName, $key, $defaultValue);
	}

	/**
	 * 	 * Set a value by key
	 * 	 *
	 *
	 * @param string $key
	 * @param string $value
	 */
	public function setAppValue(string $key, string $value): void {
		$this->config->setAppValue($this->appName, $key, $value);
	}

	/**
	 * 	 * Set a value with magic __call invocation
	 * 	 *
	 *
	 * @param string $key
	 * @param array $args
	 *
	 * @throws \BadFunctionCallException
	 */
	protected function setter(string $key, array $args): void {
		if (array_key_exists($key, $this->defaults)) {
			$this->setAppValue($key, $args[0]);
		} else {
			throw new \BadFunctionCallException($key . ' is not a valid key');
		}
	}

	/**
	 * Get a value with magic __call invocation
	 *
	 * @param string $key
	 * @return ?string
	 * @throws \BadFunctionCallException
	 */
	protected function getter(string $key): ?string {
		if (array_key_exists($key, $this->defaults)) {
			return $this->getAppValue($key);
		}

		throw new \BadFunctionCallException($key . ' is not a valid key');
	}

	/**
	 * Translates property_name into propertyName
	 *
	 * @param string $property
	 * @return string
	 */
	protected function camelCase(string $property): string {
		$split = explode('_', $property);
		$ucFirst = implode('', array_map('ucfirst', $split));
		return lcfirst($ucFirst);
	}

	/**
	 * Does all the someConfig to some_config magic
	 *
	 * @param string $property
	 * @return string
	 */
	protected function propertyToKey(string $property): string {
		$parts = preg_split('/(?=[A-Z])/', $property);
		$column = '';

		foreach ($parts as $part) {
			if ($column === '') {
				$column = $part;
			} else {
				$column .= '_' . lcfirst($part);
			}
		}

		return $column;
	}

	/**
	 * Get/set an option value by calling getSomeOption method
	 *
	 * @param string $methodName
	 * @param array $args
	 * @return ?string
	 * @throws \BadFunctionCallException
	 */
	public function __call(string $methodName, array $args): ?string {
		$attr = lcfirst(substr($methodName, 3));
		$key = $this->propertyToKey($attr);
		if (strpos($methodName, 'set') === 0) {
			$this->setter($key, $args);
			return null;
		} elseif (strpos($methodName, 'get') === 0) {
			return $this->getter($key);
		} else {
			throw new \BadFunctionCallException($methodName .
				' does not exist');
		}
	}
}
