<?php
use OC\Files\Storage\Temporary;

/**
 * Copyright (c) 2014 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */


class Test_Files_Antivirus_Scanner extends  \PHPUnit_Framework_TestCase {
	
	const TEST_CLEAN_FILENAME = 'foo.txt';
	const TEST_INFECTED_FILENAME = 'kitten.inf';

	/**
	 * @var string
	 */
	private $user;

	/**
	 * @var Temporary
	 */
	private $storage;
	
	private $config = array();
	
	public function setUp() {
		\OC_App::enable('files_antivirus');

		\OC_User::clearBackends();
		\OC_User::useBackend(new \OC_User_Dummy());
		\OC\Files\Filesystem::clearMounts();

		//login
		\OC_User::createUser('test', 'test');
		
		$this->storage = new \OC\Files\Storage\Temporary(array());
		\OC\Files\Filesystem::init('test', '');
		\OC\Files\Filesystem::clearMounts();
		\OC\Files\Filesystem::mount($this->storage, array(), '/');
		\OC\Files\Filesystem::file_put_contents(self::TEST_CLEAN_FILENAME, self::TEST_CLEAN_FILENAME);
		\OC\Files\Filesystem::file_put_contents(self::TEST_INFECTED_FILENAME, self::TEST_INFECTED_FILENAME);
		
		$this->config['av_mode'] = \OCP\Config::getAppValue('files_antivirus', 'av_mode', null);
		$this->config['av_path'] = \OCP\Config::getAppValue('files_antivirus', 'av_path', null);
		
		\OCP\Config::setAppValue('files_antivirus', 'av_mode', 'executable');
		\OCP\Config::setAppValue('files_antivirus', 'av_path', __DIR__ . '/avir.sh');
		$query = \OCP\DB::prepare('DELETE FROM `*PREFIX*files_antivirus_status`');
		$query->execute(array());
		\OCA\Files_Antivirus\Status::init();
	}
	
	public function tearDown() {
		if (!is_null($this->config['av_mode'])){
			\OCP\Config::setAppValue('files_antivirus', 'av_mode', $this->config['av_mode']);
		}
		if (!is_null($this->config['av_path'])){
			\OCP\Config::setAppValue('files_antivirus', 'av_path', $this->config['av_path']);
		}
	}
	
	public function testScanFile(){
		$fileView = new \OC\Files\View('');
		
		$cleanStatus = \OCA\Files_Antivirus\Scanner::scanFile($fileView, self::TEST_CLEAN_FILENAME);
		$this->assertInstanceOf('\OCA\Files_Antivirus\Status', $cleanStatus);
		$this->assertEquals(\OCA\Files_Antivirus\Status::SCANRESULT_CLEAN, $cleanStatus->getNumericStatus());
		
		$unknownStatus = \OCA\Files_Antivirus\Scanner::scanFile($fileView, 'non-existing.file');
		$this->assertInstanceOf('\OCA\Files_Antivirus\Status', $unknownStatus);
		$this->assertEquals(\OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED, $unknownStatus->getNumericStatus());
		
		$infectedStatus = \OCA\Files_Antivirus\Scanner::scanFile($fileView, self::TEST_INFECTED_FILENAME);
		$this->assertInstanceOf('\OCA\Files_Antivirus\Status', $infectedStatus);
		$this->assertEquals(\OCA\Files_Antivirus\Status::SCANRESULT_INFECTED, $infectedStatus->getNumericStatus());
	}
	
}
