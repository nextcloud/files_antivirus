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
use \OCA\Files_Antivirus\Appconfig;

use \OCP\AppFramework\Http\TemplateResponse;
use \OCP\AppFramework\Http\JSONResponse;

class SettingsController extends Controller {
	
	private $settings;
	
	public function __construct(IRequest $request, Appconfig $appconfig) {
		$this->settings = $appconfig;
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
	 * @param string $av_mode - antivirus mode
	 * @param string $av_socket - path to socket (Socket mode)
	 * @param string $av_host - antivirus url
	 * @param type $av_port - port
	 * @param type $av_cmd_options - extra command line options
	 * @param type $av_chunk_size - Size of one portion
	 * @param type $av_path - path to antivirus executable (Executable mode)
	 * @param type $av_infected_action - action performed on infected files
	 * @return JSONResponse
	 */
	public function save($av_mode, $av_socket, $av_host, $av_port, $av_cmd_options, $av_chunk_size, $av_path, $av_infected_action) {
		$this->settings->setAvMode($av_mode);
		$this->settings->setAvSocket($av_socket);
		$this->settings->setAvHost($av_host);
		$this->settings->setAvPort($av_port);
		$this->settings->setAvCmdOptions($av_cmd_options);
		$this->settings->setAvChunkSize($av_chunk_size);
		$this->settings->setAvPath($av_path);
		$this->settings->setAvInfectedAction($av_infected_action);
		
		return new JSONResponse($this->settings->getAllValues());
	}
}
