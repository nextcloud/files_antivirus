<?php
/**
 * Copyright (c) 2014 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus;

use Icewind\Streams\CallbackWrapper;
use OC\Files\Storage\Wrapper\Wrapper;
use OCA\Files_Antivirus\Activity\Provider;
use OCA\Files_Antivirus\AppInfo\Application;
use OCA\Files_Antivirus\Scanner\ScannerFactory;
use OCP\Activity\IManager as ActivityManager;
use OCP\App;
use OCP\Files\InvalidContentException;
use OCP\IL10N;
use OCP\ILogger;

class AvirWrapper extends Wrapper{
	
	/**
	 * Modes that are used for writing 
	 * @var array 
	 */
	private $writingModes = ['r+', 'w', 'w+', 'a', 'a+', 'x', 'x+', 'c', 'c+'];
	
	/** @var ScannerFactory */
	protected $scannerFactory;
	
	/** @var IL10N */
	protected $l10n;
	
	/** @var ILogger */
	protected $logger;

	/** @var ActivityManager */
	protected $activityManager;

	/**
	 * @param array $parameters
	 */
	public function __construct($parameters) {
		parent::__construct($parameters);
		$this->scannerFactory = $parameters['scannerFactory'];
		$this->l10n = $parameters['l10n'];
		$this->logger = $parameters['logger'];
		$this->activityManager = $parameters['activityManager'];
	}
	
	/**
	 * Asynchronously scan data that are written to the file
	 * @param string $path
	 * @param string $mode
	 * @return resource | bool
	 */
	public function fopen($path, $mode){
		$stream = $this->storage->fopen($path, $mode);
		if (is_resource($stream) && $this->isWritingMode($mode)) {
			try {
				$scanner = $this->scannerFactory->getScanner();
				$scanner->initScanner();
				return CallbackWrapper::wrap(
					$stream,
					null,
					function ($data) use ($scanner){
						$scanner->onAsyncData($data);
					}, 
					function () use ($scanner, $path) {
						$status = $scanner->completeAsyncScan();
						if ((int)$status->getNumericStatus() === Status::SCANRESULT_INFECTED){
							//prevent from going to trashbin
							if (App::isEnabled('files_trashbin')) {
								\OCA\Files_Trashbin\Storage::preRenameHook([
									'oldpath' => '',
									'newpath' => ''
								]);
							}
							
							$owner = $this->getOwner($path);
							$this->unlink($path);

							if (App::isEnabled('files_trashbin')) {
								\OCA\Files_Trashbin\Storage::preRenameHook([
									'oldpath' => '',
									'newpath' => ''
								]);
							}
							$this->logger->warning(
								'Infected file deleted. ' . $status->getDetails()
								. ' Account: ' . $owner . ' Path: ' . $path,
								['app' => 'files_antivirus']
							);

							$activity = $this->activityManager->generateEvent();
							$activity->setApp(Application::APP_NAME)
								->setSubject(Provider::SUBJECT_VIRUS_DETECTED, [$path, $status->getDetails()])
								->setMessage(Provider::MESSAGE_FILE_DELETED)
								->setObject('', 0, $path)
								->setAffectedUser($owner)
								->setType(Provider::TYPE_VIRUS_DETECTED);
							$this->activityManager->publish($activity);

							$this->logger->error('Infected file deleted. ' . $status->getDetails() . 
							' File: ' . $path . ' Acccount: ' . $owner, ['app' => 'files_antivirus']);

							throw new InvalidContentException(
								$this->l10n->t(
									'Virus %s is detected in the file. Upload cannot be completed.',
									$status->getDetails()
								)
							);
						}
					}
				);
			} catch (\Exception $e){
				$this->logger->logException($e);
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
		// Strip unessential binary/text flags
		$cleanMode = str_replace(
			['t', 'b'],
			['', ''],
			$mode
		);
		return in_array($cleanMode, $this->writingModes);
	}
}
