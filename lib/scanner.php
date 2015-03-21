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

abstract class Scanner {
	
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
	 * Close used resources
	 */
	abstract protected function shutdownScanner();
	
	/**
	 * Get a resource to write data into
	 */
	abstract protected function getWriteHandle();
	
	public function getStatus(){
		if ($this->status instanceof Status){
			return $this->status;
		}
		return new Status();
	}

	/**
	 * Synchronous scan
	 * @param IScannable $item
	 * @return Status
	 */
	public function scan(IScannable $item) {
		$this->initScanner();

		while (false !== ($chunk = $item->fread())) {
			fwrite(
					$this->getWriteHandle(), 
					$this->prepareChunk($chunk)
			);
		}
		
		$this->shutdownScanner();
		return $this->getStatus();
	}
	
	/**
	 * Async scan - prepare resources
	 */
	public function initAsyncScan(){
		$this->initScanner();
	}
	
	/**
	 * Async scan - new portion of data is available
	 * @param string $data
	 */
	public function onAsyncData($data){
		fwrite(
				$this->getWriteHandle(),
				$this->prepareChunk($data)
		);
	}
	
	/**
	 * Async scan - resource is closed
	 * @return Status
	 */
	public function completeAsyncScan(){
		$this->shutdownScanner();
		return $this->getStatus();
	}
	
	/**
	 * Open write handle. etc
	 */
	protected function initScanner(){
		$this->status = new Status();
	}

	/**
	 * Prepare chunk (if required)
	 */
	protected function prepareChunk($data){
		return $data;
	}
}
