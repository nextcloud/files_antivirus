<?php

/**
 * Copyright (c) 2016 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */


namespace OCA\Files_antivirus\Tests;

use OC\Files\Filesystem;
use OC\Files\Storage\Storage;
use OC\Files\Storage\Temporary;
use OC\Files\View;
use OCA\Files_Antivirus\AppConfig;
use OCA\Files_Antivirus\AvirWrapper;
use OCA\Files_Antivirus\ScannerFactory;
use Test\Util\User\Dummy;

// mmm. IDK why autoloader fails on this class
include_once dirname(dirname(dirname(__DIR__))) . '/tests/lib/Util/User/Dummy.php';

class AvirWrapperTest extends TestBase {
	/**
	 * @var Temporary
	 */
	private $storage;

	protected $scannerFactory;

	protected $isWrapperRegistered = false;

	public function setUp() {
		parent::setUp();
		$logger = $this->container->query('Logger');
		$this->scannerFactory = new ScannerFactory(
			$this->streamConfig,
 			$logger
		);

		\OC_User::clearBackends();
		\OC_User::useBackend(new Dummy());
		Filesystem::clearMounts();

		//login
		\OC::$server->getUserManager()->createUser('testo', 'test');
		\OC::$server->getUserSession()->login('testo', 'test');
		\OC::$server->getSession()->set('user_id', 'testo');
		\OC::$server->getUserFolder('testo');
		\OC_Util::setupFS('testo');

		$this->storage = new Temporary(array());
		if (!$this->isWrapperRegistered) {
			Filesystem::addStorageWrapper(
				'oc_avir_test',
				function ($mountPoint, $storage) use ($logger) {
					/**
					 * @var Storage $storage
					 */
					if ($storage instanceof Storage) {
						return new AvirWrapper([
							'storage' => $storage,
							'scannerFactory' => $this->scannerFactory,
							'l10n' => $this->l10n,
							'logger' => $logger
						]);
					} else {
						return $storage;
					}
				},
				1
			);
			$this->isWrapperRegistered = true;
		}
		Filesystem::init('testo', '');
	}

	/**
	 * @expectedException \OCP\Files\InvalidContentException
	 */
	/*public function testInfected(){
		$fd = Filesystem::fopen('killing bee', 'w+');
		@fwrite($fd, 'it ' . DummyClam::TEST_SIGNATURE);
		@fclose($fd);
		Filesystem::unlink('killing kee');
	}*/

	/**
	 * @expectedException \OCP\Files\InvalidContentException
	 */
	public function testBigInfected(){
		$fd = Filesystem::fopen('killing whale', 'w+');
		@fwrite($fd, str_repeat('0', DummyClam::TEST_STREAM_SIZE-2));
		@fwrite($fd, DummyClam::TEST_SIGNATURE);
		@fclose($fd);
		Filesystem::unlink('killing whale');
	}

	public function tearDown() {
		parent::tearDown();
		Filesystem::tearDown();
		\OC_Util::tearDownFS();
		\OC::$server->getUserManager()->get('testo')->delete();
	}
}
