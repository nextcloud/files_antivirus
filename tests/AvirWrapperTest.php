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
use OCA\Files_Antivirus\AvirWrapper;
use OCA\Files_antivirus\Tests\Mock\Config;
use Test\Util\User\Dummy;

// mmm. IDK why autoloader fails on this class
include_once dirname(dirname(dirname(__DIR__))) . '/tests/lib/Util/User/Dummy.php';

class AvirWrapperTest extends TestBase {
	
	const UID = 'testo';
	const PWD = 'test';

	protected $scannerFactory;

	protected $isWrapperRegistered = false;

	public static function setUpBeforeClass() {
		parent::setUpBeforeClass();
		\OC_User::clearBackends();
		\OC_User::useBackend(new Dummy());
	}

	public function setUp() {
		parent::setUp();
		if (!\OC::$server->getUserManager()->get(self::UID)) {
			\OC::$server->getUserManager()->createUser(self::UID, self::PWD);
		}

		$this->scannerFactory = new Mock\ScannerFactory(
			new Mock\Config($this->container->query('CoreConfig')),
			$this->container->query('Logger')
		);

		if (!$this->isWrapperRegistered) {
			Filesystem::addStorageWrapper(
				'oc_avir_test',
				[$this, 'wrapperCallback'],
				2
			);
			$this->isWrapperRegistered = true;
		}

		\OC::$server->getUserSession()->login(self::UID, self::PWD);
		\OC::$server->getSession()->set('user_id', self::UID);
		\OC::$server->getUserFolder(self::UID);
	}

	/**
	 * @expectedException \OCP\Files\InvalidContentException
	 */
	public function testInfected(){
		$fd = Filesystem::fopen('killing bee', 'w+');
		@fwrite($fd, 'it ' . DummyClam::TEST_SIGNATURE);
	}

	/**
	 * @expectedException \OCP\Files\InvalidContentException
	 */
	public function testBigInfected(){
		$fd = Filesystem::fopen('killing whale', 'w+');
		@fwrite($fd, str_repeat('0', DummyClam::TEST_STREAM_SIZE-2) . DummyClam::TEST_SIGNATURE );
		@fwrite($fd, DummyClam::TEST_SIGNATURE);
	}

	public function wrapperCallback($mountPoint, $storage){
		/**
		 * @var Storage $storage
		 */
		if ($storage instanceof Storage) {
			return new AvirWrapper([
				'storage' => $storage,
				'scannerFactory' => $this->scannerFactory,
				'l10n' => $this->l10n,
				'logger' => $this->container->query('Logger')
			]);
		} else {
			return $storage;
		}
	}

	public static function tearDownAfterClassClass() {
		parent::tearDownAfterClass();
		\OC::$server->getUserManager()->get(self::UID)->delete();
		\OC_User::clearBackends();
	}
}
