<?php

/**
* ownCloud - files_antivirus
*
* @author Manuel Deglado
* @copyright 2012 Manuel Deglado manuel.delgado@ucr.ac.cr
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
* License as published by the Free Software Foundation; either
* version 3 of the License, or any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU AFFERO GENERAL PUBLIC LICENSE for more details.
*
* You should have received a copy of the GNU Affero General Public
* License along with this library.  If not, see <http://www.gnu.org/licenses/>.
*
*/

namespace OCA\Files_Antivirus;

use OCP\IL10N;
use OCA\Files_Antivirus\Item;

class Scanner {

	/**
	 * A proper subclass
	 * @var Scanner
	 */
	protected $instance = null;
	
	/**
	 * Scan result
	 * @var \OCA\Files_Antivirus\Status
	 */
	protected $status;
	
	/**
	 * @var \OCA\Files_Antivirus\AppConfig
	 */
	protected $appConfig;
	
	/**
	 * @var IL10N
	 */
	protected $l10n;
	
	public function __construct($config, IL10N $l10n){
		$this->appConfig = $config;
		try {
			$avMode = $this->appConfig->getAvMode();
			switch($avMode) {
				case 'daemon':
				case 'socket':
					$this->instance = new \OCA\Files_Antivirus\Scanner\External($this->appConfig);
					break;
				case 'executable':
					$this->instance = new \OCA\Files_Antivirus\Scanner\Local($this->appConfig);
					break;
				default:
					$this->instance = false;
					\OCP\Util::writeLog('files_antivirus', 'Unknown mode: ' . $avMode, \OCP\Util::WARN);
					break;
			}
		} catch (\Exception $e){
		}
	}
	
	public function getStatus(){
		if ($this->instance->status instanceof Status){
			return $this->instance->status;
		}
		return new Status();
	}

	/**
	 * Synchronous scan
	 * @param IScannable $item
	 * @return Status
	 */
	public function scan(IScannable $item) {
		$this->instance->initScanner();

		while (false !== ($chunk = $item->fread())) {
			fwrite(
					$this->instance->getWriteHandle(), 
					$this->instance->prepareChunk($chunk)
			);
		}
		
		$this->instance->shutdownScanner();
		return $this->getStatus();
	}
	
	/**
	 * Async scan - prepare resources
	 */
	public function initAsyncScan(){
		$this->instance->initScanner();
	}
	
	/**
	 * Async scan - new portion of data is available
	 * @param string $data
	 */
	public function onAsyncData($data){
		fwrite(
				$this->instance->getWriteHandle(),
				$this->instance->prepareChunk($data)
		);
	}
	
	/**
	 * Async scan - resource is closed
	 * @return Status
	 */
	public function completeAsyncScan(){
		$this->instance->shutdownScanner();
		return $this->getStatus();
	}
	
	/**
	 * Open write handle. etc
	 */
	protected function initScanner(){
		$this->status = new Status();
	}

	/**
	 * Close used resources
	 */
	protected function shutdownScanner(){
	}
	
	/**
	 * Get a resource to write data into
	 */
	protected function getWriteHandle(){
	}

	/**
	 * Prepare chunk (if required)
	 */
	protected function prepareChunk($data){
	}
}
