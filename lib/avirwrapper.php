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

use \OCP\IConfig;
use \OCP\IL10N;
use \OCP\ILogger;
use \OCP\Files\InvalidContentException;


class AvirWrapper extends Wrapper{
	
	/**
	 * Modes that are used for writing 
	 * @var array 
	 */
	private $writingModes = array('r+', 'w', 'w+', 'a', 'a+', 'x', 'x+', 'c', 'c+');
	
	/**
	 * @var IConfig 
	 */
	protected $config;
	
	/**
	 * @var IL10N 
	 */
	protected $l10n;
	
	/**
	 * @var ILogger;
	 */
	protected $logger;

	/**
	 * @param array $parameters
	 */
	public function __construct($parameters) {
		parent::__construct($parameters);
		$this->config = $parameters['config'];
		$this->l10n = $parameters['l10n'];
		$this->logger = $parameters['logger'];
	}
	
	/**
	 * Asyncronously scan data that are written to the file
	 * @param string $path
	 * @param string $mode
	 * @return resource | bool
	 */
	public function fopen($path, $mode){
		$stream = $this->storage->fopen($path, $mode);
		if (is_resource($stream) && $this->isWritingMode($mode)) {
			try {
				$storage = $this;
				$scanner = new Scanner($this->config, $this->l10n);
				$scanner->initAsyncScan();
				return CallBackWrapper::wrap(
					$stream, 
					null,
					function ($data) use ($scanner){
						$scanner->onAsyncData($data);
					}, 
					function () use ($scanner, $storage, $path) {
						$status = $scanner->completeAsyncScan();
						if ($status->getNumericStatus() == \OCA\Files_Antivirus\Status::SCANRESULT_INFECTED){
							$storage->unlink($path);
							throw new InvalidContentException($status->getDetails());
						}
					}
				);
			} catch (\Exception $e){
				$message = 	implode(' ', [ __CLASS__, __METHOD__, $e->getMessage()]);
				$this->logger->warning($message);
			}
		}
		return $stream;
	}
	
	/**
	 * Checks whether passed mode is suitable for writing 
	 * @param string $mode
	 * @return bool
	 */
	private function isWritingMode($mode){
		return in_array($mode, $this->writingModes);
	}
}
