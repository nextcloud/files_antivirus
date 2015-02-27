<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\Cron;

use OCA\Files_Antivirus\AppInfo\Application;

class Task {
	public static function run() {
		if (!\OCP\App::isEnabled('files_antivirus')){
			return;
		}

		$application = new Application();
		$container = $application->getContainer();
		$container->query('BackgroundScanner')->run();
	}
}
