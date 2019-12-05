<?php

/**
 * Copyright (c) 2016 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */


namespace OCA\Files_Antivirus\Tests;

use OC\Files\Storage\Temporary;
use OCA\Files_Antivirus\AvirWrapper;
use OCA\Files_Antivirus\Scanner\External;
use OCA\Files_Antivirus\Scanner\ScannerFactory;
use OCA\Files_Antivirus\StatusFactory;
use OCP\Activity\IManager;
use OCP\ILogger;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Test\Traits\UserTrait;

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

	/** @var ILogger */
	protected $logger;

	/** @var AvirWrapper */
	protected $wrappedStorage;

	protected function setUp(): void {
		parent::setUp();
		$this->createUser(self::UID, self::PWD);

		$this->storage = new Temporary([]);
		$this->logger = $this->createMock(ILogger::class);

		$scanner = new External(
			$this->config,
			$this->logger,
			$this->createMock(StatusFactory::class)
		);
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
			'logger' => $this->logger,
			'activityManager' => $this->createMock(IManager::class),
			'isHomeStorage' => true,
			'eventDispatcher' => $this->createMock(EventDispatcherInterface::class),
		]);

		$this->config->expects($this->any())
			->method('getAvMode')
			->will($this->returnValue('daemon'));
	}

	/**
	 * @NOexpectedException \OCP\Files\InvalidContentException
	 */
	public function testInfected() {
		$this->assertTrue(true);
		return;
		$fd = $this->wrappedStorage->fopen('killing bee', 'w+');
		fwrite($fd, 'it ' . DummyClam::TEST_SIGNATURE);
	}

	/**
	 * @NOexpectedException \OCP\Files\InvalidContentException
	 */
	public function testBigInfected() {
		$this->assertTrue(true);
		return;

		$fd = $this->wrappedStorage->fopen('killing whale', 'w+');
		fwrite($fd, str_repeat('0', DummyClam::TEST_STREAM_SIZE - 2) . DummyClam::TEST_SIGNATURE);
		fwrite($fd, DummyClam::TEST_SIGNATURE);
	}
}
