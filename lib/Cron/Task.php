<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\Cron;

use OC\BackgroundJob\TimedJob;
use OCA\Files_Antivirus\BackgroundScanner;


class Task extends TimedJob {

	/** @var BackgroundScanner */
	private $backgroundScanner;

	/**
	 * sets the correct interval for this timed job
	 */
	public function __construct(BackgroundScanner $backgroundScanner) {
		// Run once per 15 minutes
		$this->setInterval(60 * 15);

		$this->backgroundScanner = $backgroundScanner;
	}

	protected function run($argument) {
		$this->backgroundScanner->run();
	}
}
