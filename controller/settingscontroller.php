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
	
	public function index() {
		$data = $this->settings->getAllValues();
		return new TemplateResponse('files_antivirus', 'settings', $data, 'blank');
	}
	
	public function save($av_mode, $av_socket, $av_host, $av_port, $av_cmd_options, $av_chunk_size, $av_path, $infected_action) {
		$this->settings->setAvMode($av_mode);
		$this->settings->setAvSocket($av_socket);
		$this->settings->setAvHost($av_host);
		$this->settings->setAvPort($av_port);
		$this->settings->setAvCmdOptions($av_cmd_options);
		$this->settings->setAvChunkSize($av_chunk_size);
		$this->settings->setAvPath($av_path);
		$this->settings->setAvInfectedAction($infected_action);
		
		return new JSONResponse($this->settings->getAllValues());
	}
}
