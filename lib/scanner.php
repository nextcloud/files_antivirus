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

	/**
	 * Static FS hook entry point
	 * @param string $path
	 */
	public static function avScan($path) {
		$path = $path[\OC\Files\Filesystem::signal_param_path];
		if (empty($path)) {
			return;
		}
				
		if (isset($_POST['dirToken'])){
			//Public upload case
			$filesView = \OC\Files\Filesystem::getView();
		} else {
			$filesView = \OCP\Files::getStorage("files");
		}
		
		try {
			$application = new \OCA\Files_Antivirus\AppInfo\Application();
			$appConfig = $application->getContainer()->query('AppConfig');
			$l10n = $application->getContainer()->query('L10N');
			
			$item = new Item($l10n, $filesView, $path);
			if (!$item->isValid()){
				return;
			}
		
			$scanner = new self($appConfig, $l10n);
			$fileStatus = $scanner->scan($item);
			$fileStatus->dispatch($item);
		} catch (\Exception $e){
			\OCP\Util::writeLog('files_antivirus', $e->getMessage(), \OCP\Util::ERROR);
		}
	}
	
	public function getStatus(){
		if ($this->instance->status instanceof Status){
			return $this->instance->status;
		}
		return new Status();
	}

	/**
	 * @param Item $item
	 * @return Status
	 */
	public function scan(Item $item) {
		if ($this->instance instanceof Scanner) {
			return $this->instance->scan($item);
		}
		
		return new Status();
	}
}
