<?php

/**
 * Copyright (c) 2016 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */


namespace OCA\Files_antivirus\Tests\Mock;

use \OCA\Files_antivirus\AppConfig;
use \OCA\Files_antivirus\Tests\DummyClam;

class Config extends AppConfig {
	public function getAppValue($key) {
		$map = [
			'av_host' => '127.0.0.1',
			'av_port' => 5555,
			'av_stream_max_length' => DummyClam::TEST_STREAM_SIZE,
			'av_mode' => 'daemon'
		];
		if (array_key_exists($key, $map)){
			return $map[$key];
		}
		return '';
	}
}