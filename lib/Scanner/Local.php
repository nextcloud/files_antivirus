<?php
/**
 * Copyright (c) 2014 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */


namespace OCA\Files_Antivirus\Scanner;

class Local extends \OCA\Files_Antivirus\Scanner{
	
	/**
	 * @var string
	 */
	protected $avPath;
	
	/**
	 * STDIN and STDOUT descriptors
	 * @var array of resources
	 */
	private $pipes = [];
	
	/**
	 * Process handle
	 * @var resource
	 */
	private $process;
	
	public function __construct($config){
		$this->appConfig = $config;
		// get the path to the executable
		$this->avPath = escapeshellcmd($this->appConfig->getAvPath());

		// check that the executable is available
		if (!file_exists($this->avPath)) {
			throw new \RuntimeException('The antivirus executable could not be found at ' . $this->avPath);
		}
	}
	
	public function initScanner(){
		parent::initScanner();
		
		// using 2>&1 to grab the full command-line output.
		$cmd = $this->avPath . " " . $this->appConfig->getCmdline() ." - 2>&1";
		$descriptorSpec = array(
			0 => ["pipe","r"], // STDIN
			1 => ["pipe","w"]  // STDOUT
		);
		
		$this->process = proc_open($cmd, $descriptorSpec, $this->pipes);
		if (!is_resource($this->process)) {
			throw new \RuntimeException('Error starting process');
		}
		$this->writeHandle = $this->pipes[0];
	}
	
	protected function shutdownScanner(){
		@fclose($this->pipes[0]);
		$output = stream_get_contents($this->pipes[1]);
		@fclose($this->pipes[1]);
		
		$result = proc_close($this->process);
		\OC::$server->getLogger()->debug(
			'Exit code :: ' . $result . ' Response :: ' . $output,
			['app' => 'files_antivirus']
		);
		$this->status->parseResponse($output, $result);
	}
}
