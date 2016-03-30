<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\Cron;

use OC\BackgroundJob\TimedJob;
use OCA\Files_Antivirus\AppInfo\Application;


class Task extends TimedJob {

	/**
	 * sets the correct interval for this timed job
	 */
	public function __construct() {
		// Run once per 15 minutes
		$this->setInterval(60 * 15);
	}

	protected function run($argument) {
		if (!\OCP\App::isEnabled('files_antivirus')){
			return;
		}

		$application = new Application();
		$container = $application->getContainer();
		$container->query('BackgroundScanner')->run();
	}
}
