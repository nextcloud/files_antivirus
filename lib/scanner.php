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

	/** @var  int */
	protected $byteCount;

	/** @var  resource */
	protected $writeHandle;

	/** @var \OCA\Files_Antivirus\AppConfig */
	protected $appConfig;

	/** @var bool */
	protected $isLogUsed;

	/**
	 * Close used resources
	 */
	abstract protected function shutdownScanner();


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
			$this->writeChunk($chunk);
		}
		
		$this->shutdownScanner();
		return $this->getStatus();
	}
	
	/**
	 * Async scan - new portion of data is available
	 * @param string $data
	 */
	public function onAsyncData($data){
		$this->writeChunk($data);
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
	public function initScanner(){
		$this->byteCount = 0;
		$this->status = new Status();
	}

	/**
	 * @param string $chunk
	 */
	protected function writeChunk($chunk){
		$this->fwrite(
			$this->prepareChunk($chunk)
		);
	}

	/**
	 * @param string $data
	 */
	protected final function fwrite($data){
		$dataLength = strlen($data);
		$fileSizeLimit = intval($this->appConfig->getAvMaxFileSize());
		if ($fileSizeLimit !== -1 && $this->byteCount + $dataLength > $fileSizeLimit){
			$this->shutdownScanner();
			$this->initScanner();
		}

		$bytesWritten = @fwrite($this->getWriteHandle(), $data);
		if ($bytesWritten === false || $bytesWritten < $dataLength){
			if (!$this->isLogUsed) {
				$this->isLogUsed = true;
				\OC::$server->getLogger()->warning(
					'Failed to write a chunk. File is too big?',
					['app' => 'files_antivirus']
				);
			}
			// retry
			$this->initScanner();
			@fwrite($this->getWriteHandle(), $data);
		} else {
			$this->byteCount += $bytesWritten;
		}
	}

	/**
	 * Get a resource to write data into
	 * @return resource
	 */
	protected function getWriteHandle(){
		return $this->writeHandle;
	}

	/**
	 * Prepare chunk (if required)
	 * @param string $data
	 * @return string
	 */
	protected function prepareChunk($data){
		return $data;
	}
}
