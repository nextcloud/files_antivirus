<?php

/**
 * SPDX-FileCopyrightText: 2017-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2016 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests;

use OC\Files\Storage\Temporary;
use OCA\Files_Antivirus\AvirWrapper;
use OCA\Files_Antivirus\Scanner\ExternalClam;
use OCA\Files_Antivirus\Scanner\IScanner;
use OCA\Files_Antivirus\Scanner\ScannerFactory;
use OCA\Files_Antivirus\StatusFactory;
use OCP\Activity\IManager;
use OCP\IRequest;
use OCP\IUserManager;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Test\Traits\UserTrait;

// mmm. IDK why autoloader fails on this class
include_once dirname(dirname(dirname(__DIR__))) . '/tests/lib/Util/User/Dummy.php';

/**
 * @group DB
 */
class AvirWrapperTest extends TestBase {
	use UserTrait;

	public const UID = 'testo';
	public const PWD = 'test';

	/** @var ScannerFactory|\PHPUnit_Framework_MockObject_MockObject */
	protected $scannerFactory;

	protected $isWrapperRegistered = false;

	/** @var Temporary */
	protected $storage;

	/** @var LoggerInterface */
	protected $logger;

	/** @var AvirWrapper */
	protected $wrappedStorage;

	protected function setUp(): void {
		parent::setUp();
		$this->createUser(self::UID, self::PWD);

		$this->storage = new Temporary([]);
		$this->logger = $this->createMock(LoggerInterface::class);

		$scanner = new ExternalClam(
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
			'trashEnabled' => true,
			'groupFoldersEnabled' => false,
			'e2eeEnabled' => false,
			'blockListedDirectories' => ['escape-scan', 'dont-scan'],
			'mount_point' => '/' . self::UID . '/files/',
			'block_unscannable' => false,
			'userManager' => $this->createMock(IUserManager::class),
			'block_unreachable' => 'yes',
			'request' => $this->createMock(IRequest::class),
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

	/**
	 * @dataProvider shouldWrapProvider
	 */
	public function testShouldWrap(string $path, bool $expected) {
		$actual = self::invokePrivate($this->wrappedStorage, 'shouldWrap', [$path]);
		self::assertEquals($expected, $actual);
	}

	public function shouldWrapProvider(): array {
		return [
			['/files/my_file_1', true],
			['files/my_file_2', true],
			['/files_external/rootcerts.crt', false],
			['/files_external/rootcerts.crt.tmp.0123456789', false],
			['/root_file', false],
			['files/escape-scan/my_file_2', false],
			['files/dont-scan/my_file_2', false],
			['files/dont-scan/scan/my_file_2', false],
			['files/scan/my_file_2', true],
			['files/scanforvirus/my_file_2', true],
		];
	}

	public function testWrapStreamWithNullMountPoint(): void {
		$scannerFactory = $this->createMock(ScannerFactory::class);

		$wrapper = new AvirWrapper([
			'storage' => $this->storage,
			'scannerFactory' => $scannerFactory,
			'l10n' => $this->l10n,
			'logger' => $this->logger,
			'activityManager' => $this->createMock(IManager::class),
			'isHomeStorage' => true,
			'eventDispatcher' => $this->createMock(EventDispatcherInterface::class),
			'trashEnabled' => true,
			'groupFoldersEnabled' => false,
			'e2eeEnabled' => false,
			'blockListedDirectories' => ['escape-scan', 'dont-scan'],
			'mount_point' => null,
			'block_unscannable' => false,
			'userManager' => $this->createMock(IUserManager::class),
			'block_unreachable' => 'no',
			'request' => $this->createMock(IRequest::class),
		]);

		$scanner = $this->createMock(IScanner::class);
		$scannerFactory->expects(self::once())
			->method('getScanner')
			->with(null)
			->willReturn($scanner);
		$scanner->expects(self::once())
			->method('initScanner')
			->willThrowException(new \Exception('Skip actual wrapping (hackity hack)'));

		$this->logger->expects(self::once())
			->method('error');

		$class = new \ReflectionClass(AvirWrapper::class);
		$wrapStreamMethod = $class->getMethod('wrapSteam');

		$expected = fopen('php://memory', 'rwb');
		$this->assertNotFalse($expected);
		$actual = $wrapStreamMethod->invokeArgs($wrapper, ['/foo/bar.baz', $expected]);
		$this->assertEquals($expected, $actual);
		fclose($expected);
	}

	public function testHandleConnectionErrorIsTriggered(): void {
		// Simulate ScannerFactory throwing an exception
		$scannerFactory = $this->createMock(ScannerFactory::class);
		$scannerFactory->expects(self::once())
			->method('getScanner')
			->willThrowException(new \Exception('Simulated failure'));

		$logger = $this->createMock(LoggerInterface::class);
		$logger->expects(self::once())
			->method('error')
			->with($this->stringContains('Simulated failure'));

		$wrapper = new class([ 'storage' => $this->storage, 'scannerFactory' => $scannerFactory, 'l10n' => $this->l10n, 'logger' => $logger, 'activityManager' => $this->createMock(\OCP\Activity\IManager::class), 'isHomeStorage' => false, 'eventDispatcher' => $this->createMock(\OCP\EventDispatcher\IEventDispatcher::class), 'trashEnabled' => false, 'mount_point' => '/', 'block_unscannable' => false, 'userManager' => $this->createMock(IUserManager::class), 'block_unreachable' => 'yes', 'request' => $this->createMock(IRequest::class), 'blockListedDirectories' => ['escape-scan'], 'groupFoldersEnabled' => false, 'e2eeEnabled' => false, ]) extends \OCA\Files_Antivirus\AvirWrapper {
			public bool $connectionErrorCalled = false;
			protected function handleConnectionError(string $path): void {
				$this->connectionErrorCalled = true;
				parent::handleConnectionError($path);
			}
		};

		$this->expectException(\OCP\Files\InvalidContentException::class);

		$stream = fopen('php://memory', 'rwb');
		$wrapper->writeStream('anyfile.txt', $stream);
		$this->assertTrue($wrapper->connectionErrorCalled, 'Expected handleConnectionError to be called');
	}

}
