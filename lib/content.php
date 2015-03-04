<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus;

class Content implements IScannable{
	
	protected $content;
	
	protected $storage;
	
	protected $currentPosition = 0;
	
	protected $chunkSize;
	
	public function __construct($content, $storage){
		$this->content = $content;
		$this->storage = $storage;
		$application = new \OCA\Files_Antivirus\AppInfo\Application();
		$config = $application->getContainer()->query('AppConfig');
		$this->chunkSize = $config->getAvChunkSize();
	}
	
	public function fread(){
		if ($this->currentPosition >=  strlen($this->content)) {
			return false;
		}
		$chunk = substr($this->content, $this->currentPosition, $this->chunkSize);
		$this->currentPosition = $this->currentPosition + $this->chunkSize;
		
		return $chunk;
	}
}
