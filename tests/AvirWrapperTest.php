<?php

/**
 * Copyright (c) 2016 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */


namespace OCA\Files_Antivirus\Tests;

use OC\Files\Filesystem;
use OC\Files\Storage\Storage;
use OC\Files\Storage\StorageFactory;
use OC\Files\Storage\Temporary;
use OCA\Files_Antivirus\AvirWrapper;
use OCA\Files_Antivirus\Scanner\External;
use OCA\Files_Antivirus\ScannerFactory;
use Test\Traits\UserTrait;
use Test\Util\User\Dummy;

// mmm. IDK why autoloader fails on this class
include_once dirname(dirname(dirname(__DIR__))) . '/tests/lib/Util/User/Dummy.php';

/**
 * @group DB
 */
class AvirWrapperTest extends TestBase {
	use UserTrait;

	const UID = 'testo';
	const PWD = 'test';

	/** @var ScannerFactory|\PHPUnit_Framework_MockObject_MockObject */
	protected $scannerFactory;

	protected $isWrapperRegistered = false;

	/** @var Temporary */
	protected $storage;

	/** @var AvirWrapper */
	protected $wrappedStorage;

	public function setUp() {
		parent::setUp();
		$this->createUser(self::UID, self::PWD);

		$this->storage = new Temporary([]);

		$scanner = new External($this->config);
		$this->scannerFactory = $this->getMockBuilder(ScannerFactory::class)
			->disableOriginalConstructor()
			->getMock();

		$this->scannerFactory->expects($this->any())
			->method('getScanner')
			->willReturn($scanner);

		\OC::$server->getUserSession()->login(self::UID, self::PWD);

		$this->wrappedStorage = new AvirWrapper([
			'storage' => $this->storage,
			'scannerFactory' => $this->scannerFactory,
			'l10n' => $this->l10n,
			'logger' => $this->container->query('Logger')
		]);

		$this->config->expects($this->any())
			->method('getAvMode')
			->will($this->returnValue('daemon'));
	}

	/**
	 * @expectedException \OCP\Files\InvalidContentException
	 */
	public function testInfected() {
		$fd = $this->wrappedStorage->fopen('killing bee', 'w+');
		fwrite($fd, 'it ' . DummyClam::TEST_SIGNATURE);
	}

	/**
	 * @expectedException \OCP\Files\InvalidContentException
	 */
	public function testBigInfected() {
		$fd = $this->wrappedStorage->fopen('killing whale', 'w+');
		fwrite($fd, str_repeat('0', DummyClam::TEST_STREAM_SIZE - 2) . DummyClam::TEST_SIGNATURE);
		fwrite($fd, DummyClam::TEST_SIGNATURE);
	}
}
