<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus;

use \OCP\IConfig;

class Appconfig {
	private $appName = 'files_antivirus';
	private $config;

	private $defaults = array(
		'av_mode' => 'executable',
		'av_socket' => '/var/run/clamav/clamd.ctl',
		'av_host' => '',
		'av_port' => '',
		'av_cmd_options' => '',
		'av_chunk_size' => '1024',
		'av_path' => '/usr/bin/clamscan',
		'av_infected_action' => 'only_log',
	);

	/**
	 * @method string getAvMode()
	 * @method string getAvSocket()
	 * @method string getAvHost()
	 * @method int getAvPort()
	 * @method string getAvCmdOptions()
	 * @method int getChunkSize()
	 * @method string getAvPath()
	 * @method string getAvInfectedAction()
	 * 
	 * @method null setAvMode()
	 * @method null setAvSocket()
	 * @method null setAvHost()
	 * @method null setAvPort()
	 * @method null setAvCmdOptions()
	 * @method null setChunkSize()
	 * @method null setAvPath()
	 * @method null setAvInfectedAction()
	 */

	
	public function __construct(IConfig $config) {
		$this->config = $config;
	}
	
	/**
	 * Get all setting values as an array
	 * @return array
	 */
	public function getAllValues() {
		$keys = array_keys($this->defaults);
		$values = array_map(array($this, 'getAppValue'), $keys);
		return array_combine($keys, $values);
	}
	
	/**
	 * Get a value by key
	 * @param string $key
	 * @return string
	 */
	public function getAppValue($key) {
		$defaultValue = null;
		if (array_key_exists($key, $this->defaults)){
			$defaultValue = $this->defaults[$key];
		}
		return $this->config->getAppValue($this->appName, $key, $defaultValue);
	}

	/**
	 * Set a value by key
	 * @param string $key
	 * @param string $value
	 * @return string
	 */
	public function setAppvalue($key, $value) {
		return $this->config->setAppValue($this->appName, $key, $value);
	}
	
	/**
	 * Set a value with magic __call invocation
	 * @param string $key
	 * @param array $args
	 * @throws \BadFunctionCallException
	 */
	protected function setter($key, $args) {
		if (array_key_exists($key, $this->defaults)) {
			$this->setAppvalue($key, $args[0]);
		} else {
			throw new \BadFunctionCallException($key . ' is not a valid key');
		}
	}

	/**
	 * Get a value with magic __call invocation
	 * @param string $key
	 * @return string
	 * @throws \BadFunctionCallException
	 */
	protected function getter($key) {
		if (array_key_exists($key, $this->defaults)) {
			return $this->getAppValue($key);
		} else {
			throw new \BadFunctionCallException($key . ' is not a valid key');
		}
	}
	
	/**
	 * Does all the someConfig to some_config magic
	 * @param string $property
	 * @return string
	 */
	protected function propertyToKey($property){
		$parts = preg_split('/(?=[A-Z])/', $property);
		$column = null;

		foreach($parts as $part){
			if($column === null){
				$column = $part;
			} else {
				$column .= '_' . lcfirst($part);
			}
		}

		return $column;
	}
	
	/**
	 * Get/set an option value by calling getSomeOption method
	 * @param string $methodName
	 * @param array $args
	 * @return string|null
	 * @throws \BadFunctionCallException
	 */
	public function __call($methodName, $args){
		$attr = lcfirst( substr($methodName, 3) );
		$key = $this->propertyToKey($attr);
		if(strpos($methodName, 'set') === 0){
			$this->setter($key, $args);
		} elseif(strpos($methodName, 'get') === 0) {
			return $this->getter($key);
		} else {
			throw new \BadFunctionCallException($methodName . 
					' does not exist');
		}
	}
}
