<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\AppInfo;

use \OCP\AppFramework\App;
use OCA\Files_Antivirus\Controller\RuleController;
use OCA\Files_Antivirus\Controller\SettingsController;
use OCA\Files_Antivirus\Appconfig;

class Application extends App {
	public function __construct (array $urlParams = array()) {
		parent::__construct('files_antivirus', $urlParams);
		
		$container = $this->getContainer();
		$container->registerService('Appconfig', function($c) {
			return new Appconfig(
				$c->query('CoreConfig')
			);
		});
		/**
		 * Controllers
		 */
		$container->registerService('RuleController', function($c) {
			return new RuleController(
				$c->query('AppName'),
				$c->query('Request'),
				$c->query('Logger'),
				$c->query('L10N')
			);
		});
		$container->registerService('SettingsController', function($c) {
			return new SettingsController(
				$c->query('Request'),
				$c->query('Appconfig')
			);
		});
		
		/**
		 * Core
		 */
		$container->registerService('Logger', function($c) {
			return $c->query('ServerContainer')->getLogger();
		});
        $container->registerService('CoreConfig', function($c) {
            return $c->query('ServerContainer')->getConfig();
        });
        $container->registerService('L10N', function($c) {
            return $c->query('ServerContainer')->getL10N($c->query('AppName'));
        });
	}
}
