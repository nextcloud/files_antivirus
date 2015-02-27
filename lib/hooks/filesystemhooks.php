<?php

/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\Hooks;

use \OCA\Files_Antivirus\AppConfig;

class FilesystemHooks {
	
	/**
	 * @var AppConfig
	 */
	private $appConfig;
	
	/**
	 *
	 * @var type 
	 */
	private $rootFolder;

	public function __construct($rootFolder, AppConfig $appConfig) {
		$this->rootFolder = $rootFolder;
		$this->appConfig = $appConfig;
	}

	/**
	 * Register postWrite hook listener
	 */
	public function register(){
		\OCP\Util::connectHook('OC_Filesystem', 'post_write', '\OCA\Files_Antivirus\Scanner', 'avScan');
		/* This is correct. But it doesn't work sadly
		$callback = function(\OCP\Files\Node $node) {
			exit();
		};
		$this->rootFolder->listen('\OC\Files', 'postWrite', $callback); 
		 */
	}

}
