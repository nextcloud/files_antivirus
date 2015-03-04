<?php
/**
 * Copyright (c) 2014 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus;

use OC\Files\Storage\Wrapper\Wrapper;
use OCA\Files_Antivirus\Scanner;
use OCA\Files_Antivirus\Content;

class AvirWrapper extends Wrapper{
	
	public function file_put_contents($path, $data){
		if (!$this->storage->is_dir($path)) {
			$application = new \OCA\Files_Antivirus\AppInfo\Application();
			$appConfig = $application->getContainer()->query('AppConfig');
			$l10n = $application->getContainer()->query('L10N');
			
			$content = new Content($data, $this->storage);
			
			$scanner = new Scanner($appConfig, $l10n);
			$status = $scanner->scan($content);
		}
		return $this->storage->file_put_contents($path, $data);
	}
	
	public static function setupWrapper() {
		\OC\Files\Filesystem::addStorageWrapper('oc_avir', function ($mountPoint, $storage) {
			/**
			 * @var \OC\Files\Storage\Storage $storage
			 */
			if ($storage instanceof \OC\Files\Storage\Storage && $storage->isLocal()) {
				return new \OCA\Files_Antivirus\AvirWrapper(array('storage' => $storage));
			} else {
				return $storage;
			}
		});
	}
}
