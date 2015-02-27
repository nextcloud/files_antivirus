<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\Controller;

use \OCP\AppFramework\Controller;
use \OCP\IRequest;
use \OCP\IL10N;
use \OCA\Files_Antivirus\AppConfig;

use \OCP\AppFramework\Http\TemplateResponse;
use \OCP\AppFramework\Http\JSONResponse;

class SettingsController extends Controller {

	/**
	 * @var AppConfig
	 */
	private $settings;
	
	/**
	 * @var IL10N
	 */
	private $l10n;
	
	public function __construct(IRequest $request, AppConfig $appconfig, IL10N $l10n) {
		$this->settings = $appconfig;
		$this->l10n = $l10n;
	}
	
	/**
	 * Print config section
	 * @return TemplateResponse
	 */
	public function index() {
		$data = $this->settings->getAllValues();
		return new TemplateResponse('files_antivirus', 'settings', $data, 'blank');
	}
	
	/**
	 * Save Parameters
	 * @param string $avMode - antivirus mode
	 * @param string $avSocket - path to socket (Socket mode)
	 * @param string $avHost - antivirus url
	 * @param int $avPort - port
	 * @param string $avCmdOptions - extra command line options
	 * @param int $avChunkSize - Size of one portion
	 * @param string $avPath - path to antivirus executable (Executable mode)
	 * @param string $avInfectedAction - action performed on infected files
	 * @return JSONResponse
	 */
	public function save($avMode, $avSocket, $avHost, $avPort, $avCmdOptions, $avChunkSize, $avPath, $avInfectedAction) {
		$this->settings->setAvMode($avMode);
		$this->settings->setAvSocket($avSocket);
		$this->settings->setAvHost($avHost);
		$this->settings->setAvPort($avPort);
		$this->settings->setAvCmdOptions($avCmdOptions);
		$this->settings->setAvChunkSize($avChunkSize);
		$this->settings->setAvPath($avPath);
		$this->settings->setAvInfectedAction($avInfectedAction);
		
		return new JSONResponse(
			array('data' =>
				array('message' =>
					(string) $this->l10n->t('Saved')
				),
				'status' => 'success',
				'settings' => $this->settings->getAllValues()
			)
		);
	}
}
