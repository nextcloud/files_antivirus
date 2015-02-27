<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\AppInfo;

use \OCP\AppFramework\App;

use OCA\Files_Antivirus\AppConfig;
use OCA\Files_Antivirus\Controller\RuleController;
use OCA\Files_Antivirus\Controller\SettingsController;
use OCA\Files_Antivirus\Hooks\FilesystemHooks;
use OCA\Files_Antivirus\Db\RuleMapper;
use OCA\Files_Antivirus\BackgroundScanner;

class Application extends App {
	public function __construct (array $urlParams = array()) {
		parent::__construct('files_antivirus', $urlParams);
		
		$container = $this->getContainer();
		$container->registerService('RuleController', function($c) {
			return new RuleController(
				$c->query('AppName'),
				$c->query('Request'),
				$c->query('Logger'),
				$c->query('L10N'),
				$c->query('RuleMapper')
			);
		});
		$container->registerService('SettingsController', function($c) {
			return new SettingsController(
				$c->query('Request'),
				$c->query('AppConfig'),
				$c->query('L10N')	
			);
		});
		$container->registerService('AppConfig', function($c) {
			return new AppConfig(
				$c->query('CoreConfig')
			);
		});
		
        $container->registerService('BackgroundScanner', function($c) {
			return new BackgroundScanner(
				$c->query('AppConfig'),
				$c->query('ServerContainer')->getUserManager(),
				$c->query('L10N')
			);
        });
        $container->registerService('FilesystemHooks', function($c) {
			return new FilesystemHooks(
				$c->query('ServerContainer')->getRootFolder(),
				$c->query('AppConfig')
			);
        });
        $container->registerService('RuleMapper', function($c) {
			return new RuleMapper(
				$c->query('ServerContainer')->getDb()
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
