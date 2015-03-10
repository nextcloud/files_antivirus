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
use Icewind\Streams\CallbackWrapper;

class AvirWrapper extends Wrapper{
	
	/**
	 * Modes that are used for writing 
	 * @var array 
	 */
	private $writingModes = array('r+', 'w', 'w+', 'a', 'a+', 'x', 'x+', 'c', 'c+');
	
	public function fopen($path, $mode){
		$stream = $this->storage->fopen($path, $mode);
		if (is_resource($stream)
				&& $this->file_exists($path) 
				&& $this->is_file($path) 
				&& $this->isWritingMode($mode)
		) {
			try {
				$application = new \OCA\Files_Antivirus\AppInfo\Application();
				$config = $application->getContainer()->query('AppConfig');
				$l10n = $application->getContainer()->query('L10N');
				$scanner = new Scanner($config, $l10n);
				$scanner->initAsyncScan();
				return CallBackWrapper::wrap(
					$stream, 
					null,
					function ($data) use ($scanner){
						$scanner->onAsyncData($data);
					}, 
					function () use ($scanner) {
						$status = $scanner->completeAsyncScan();
					}
				);
			} catch (\Exception $e){
				
			}
		}
		return $stream;
	}
		/*
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
	} */
	
	public static function setupWrapper(){
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
	
	private function isWritingMode($mode){
		return in_array($mode, $this->writingModes);
	}
}
