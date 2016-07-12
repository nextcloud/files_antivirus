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
use OCA\Files_Antivirus\Db\RuleMapper;
use OCA\Files_Antivirus\BackgroundScanner;
use OCA\Files_Antivirus\ScannerFactory;

use \OCA\Files_Antivirus\AvirWrapper;

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
		
        $container->registerService('ScannerFactory', function($c) {
			return new ScannerFactory(
				$c->query('AppConfig'),
				$c->query('Logger')
			);
        });
		
        $container->registerService('BackgroundScanner', function($c) {
			return new BackgroundScanner(
				$c->query('ScannerFactory'),
				$c->query('L10N'),
				$c->getServer()->getRootFolder(),
				$c->getServer()->getUserSession()
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
	
	/**
	 * Add wrapper for local storages
	 */
	public function setupWrapper(){
		\OC\Files\Filesystem::addStorageWrapper(
			'oc_avir',
			function ($mountPoint, $storage) {
				/**
				 * @var \OC\Files\Storage\Storage $storage
				 */
				if ($storage instanceof \OC\Files\Storage\Storage) {
					$scannerFactory = $this->getContainer()->query('ScannerFactory');
					$l10n = $this->getContainer()->query('L10N');
					$logger = $this->getContainer()->query('Logger');
					return new AvirWrapper([
						'storage' => $storage,
						'scannerFactory' => $scannerFactory,
						'l10n' => $l10n,
						'logger' => $logger
					]);
				} else {
					return $storage;
				}
			},
			1
		);
	}
}
