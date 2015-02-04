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
		'infected_action' => 'only_log',
	);

	
	public function __construct(IConfig $config) {
		$this->config = $config;
	}
	
	public function getAllValues() {
		$keys = array_keys($this->defaults);
		$values = array_map(array($this, 'getAppValue'), $keys);
		return array_combine($keys, $values);
	}
	
	public function getAppValue($key) {
		$defaultValue = null;
		if (in_array($key, $this->defaults)){
			$defaultValue = $this->defaults[$key];
		}
		return $this->config->getAppValue($this->appName, $key, $defaultValue);
	}
	
	public function setAvMode($value) {
		return $this->setAppValue('av_mode', $value);
	}

	public function setAvSocket($value) {
		return $this->setAppValue('av_socket', $value);
	}

	public function setAvHost($value) {
		return $this->setAppValue('av_host', $value);
	}

	public function setAvPort($value) {
		return $this->setAppValue('av_port', $value);
	}

	public function setAvCmdOptions($value) {
		return $this->setAppValue('av_cmd_options', $value);
	}

	public function setAvChunkSize($value) {
		return $this->setAppValue('av_chunk_size', $value);
	}

	public function setAvPath($value) {
		return $this->setAppValue('av_path', $value);
	}

	public function setAvInfectedAction($value) {
		return $this->setAppValue('infected_action', $value);
	}
	
	public function setAppvalue($key, $value) {
		return $this->config->setAppValue($this->appName, $key, $value);
	}
}
