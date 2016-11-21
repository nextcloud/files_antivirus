<?php

/**
 * Copyright (c) 2016 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */


namespace OCA\Files_antivirus\Tests\Mock;

use OCA\Files_Antivirus\Scanner\External;

class ScannerFactory extends \OCA\Files_antivirus\ScannerFactory{
	public function getScanner() {
		return new External($this->appConfig);
	}
}
