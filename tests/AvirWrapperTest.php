<?php

/**
 * SPDX-FileCopyrightText: 2017-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2016 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests;

use OC\Files\Storage\Temporary;
use OCA\Files_Antivirus\AppInfo\ConfigLexicon;
use OCA\Files_Antivirus\AvirWrapper;
use OCA\Files_Antivirus\Scanner\IScanner;
use OCA\Files_Antivirus\Scanner\ScannerFactory;
use OCA\Files_Antivirus\Status;
use OCP\Activity\IManager;
use OCP\IRequest;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Test\Traits\UserTrait;

// mmm. IDK why autoloader fails on this class
include_once dirname(dirname(dirname(__DIR__))) . '/tests/lib/Util/User/Dummy.php';

#[Group('DB')]
class AvirWrapperTest extends TestBase {
	use UserTrait;

	public const UID = 'testo';
	public const PWD = 'test';

	protected ScannerFactory&MockObject $scannerFactory;
	protected LoggerInterface&MockObject $logger;
	protected Temporary $storage;
	protected AvirWrapper $wrappedStorage;
	protected $isWrapperRegistered = false;

	protected function setUp(): void {
		parent::setUp();
		$this->createUser(self::UID, self::PWD);

		$this->storage = new Temporary([]);
		$this->logger = $this->createMock(LoggerInterface::class);

		$this->scannerFactory = $this->getMockBuilder(ScannerFactory::class)
			->disableOriginalConstructor()
			->getMock();

		$this->scannerFactory->expects($this->any())
			->method('getScanner')
			->willReturn($this->getScanner());

		Server::get(IUserSession::class)->login(self::UID, self::PWD);

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
			'block_unreachable' => false,
			'request' => $this->createMock(IRequest::class),
		]);

		$this->config->expects($this->any())
			->method('getAppValueString')
			->willReturnCallback(fn (string $key) => match ($key) {
				ConfigLexicon::AV_MODE => 'daemon',
				default => $this->getAppValue($key),
			});
	}

	private function getScanner($statusCode = Status::SCANRESULT_CLEAN): IScanner {
		$status = $this->createMock(Status::class);
		$status->method('getNumericStatus')
			->willReturn($statusCode);
		$scanner = $this->createMock(IScanner::class);
		$scanner->method('getStatus')
			->willReturn($status);
		$scanner = $this->createMock(IScanner::class);
		$scanner->method('scan')
			->willReturn($status);
		$scanner = $this->createMock(IScanner::class);
		$scanner->method('completeAsyncScan')
			->willReturn($status);
		$scanner = $this->createMock(IScanner::class);
		$scanner->method('scanString')
			->willReturn($status);
		return $scanner;
	}

	#[DataProvider('shouldWrapProvider')]
	public function testShouldWrap(string $path, bool $expected) {
		$actual = $this->wrappedStorage->shouldWrap($path);
		self::assertEquals($expected, $actual);
	}

	public static function shouldWrapProvider(): array {
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

	public function testCleanFileShouldAllowUpload(): void {
		$scanner = $this->getScanner(Status::SCANRESULT_CLEAN);

		$stream = fopen('php://memory', 'rwb');
		$this->assertNotFalse($stream);
		fwrite($stream, 'clean content');
		rewind($stream);

		// Should not throw exception
		$result = $this->wrappedStorage->wrapSteam('/files/test.txt', $stream, $scanner);
		$this->assertNotNull($result);
		// Consume stream to trigger scanning callbacks
		stream_get_contents($result);
		fclose($result);
	}

	public function testInfectedFileShouldBlockUpload(): void {
		$scanner = $this->getScanner(Status::SCANRESULT_INFECTED);

		$stream = fopen('php://memory', 'rwb');
		$this->assertNotFalse($stream);
		fwrite($stream, 'infected content');
		rewind($stream);

		// wrapSteam catches exceptions and logs them, doesn't propagate
		// The file would be handled (logged) but wrapped stream is returned
		$result = $this->wrappedStorage->wrapSteam('/files/test.txt', $stream, $scanner);
		$this->assertNotNull($result);
		// Consume stream to trigger scanning callbacks
		stream_get_contents($result);
		fclose($result);
	}

	#[DataProvider('unscannableFilesProvider')]
	public function testUnscannableFile(bool $blockUnscannable, bool $shouldThrow): void {
		$storage = new Temporary([]);
		$wrappedStorage = new AvirWrapper([
			'storage' => $storage,
			'scannerFactory' => $this->scannerFactory,
			'l10n' => $this->l10n,
			'logger' => $this->logger,
			'activityManager' => $this->createMock(IManager::class),
			'isHomeStorage' => true,
			'eventDispatcher' => $this->createMock(EventDispatcherInterface::class),
			'trashEnabled' => true,
			'groupFoldersEnabled' => false,
			'e2eeEnabled' => false,
			'blockListedDirectories' => [],
			'mount_point' => '/user/files/',
			'block_unscannable' => $blockUnscannable,
			'userManager' => $this->createMock(IUserManager::class),
			'block_unreachable' => false,
			'request' => $this->createMock(IRequest::class),
		]);

		$scanner = $this->getScanner(Status::SCANRESULT_UNSCANNABLE);

		$stream = fopen('php://memory', 'rwb');
		$this->assertNotFalse($stream);
		fwrite($stream, 'unscannable content');
		rewind($stream);

		// wrapSteam catches exceptions and doesn't propagate them
		$result = $wrappedStorage->wrapSteam('/files/test.txt', $stream, $scanner);
		$this->assertNotNull($result);
		// Consume stream to trigger scanning callbacks
		stream_get_contents($result);
		fclose($result);
	}

	public static function unscannableFilesProvider(): array {
		return [
			'unscannable with block enabled' => [true, true],
			'unscannable with block disabled' => [false, false],
		];
	}

	#[DataProvider('unreachableAVProvider')]
	public function testUnreachableAV(bool $blockUnreachable, string $description): void {
		$storage = new Temporary([]);
		$wrappedStorage = new AvirWrapper([
			'storage' => $storage,
			'scannerFactory' => $this->scannerFactory,
			'l10n' => $this->l10n,
			'logger' => $this->logger,
			'activityManager' => $this->createMock(IManager::class),
			'isHomeStorage' => true,
			'eventDispatcher' => $this->createMock(EventDispatcherInterface::class),
			'trashEnabled' => true,
			'groupFoldersEnabled' => false,
			'e2eeEnabled' => false,
			'blockListedDirectories' => [],
			'mount_point' => '/user/files/',
			'block_unscannable' => false,
			'userManager' => $this->createMock(IUserManager::class),
			'block_unreachable' => $blockUnreachable,
			'request' => $this->createMock(IRequest::class),
		]);

		$scanner = $this->getScanner(Status::SCANRESULT_UNCHECKED);

		$stream = fopen('php://memory', 'rwb');
		$this->assertNotFalse($stream);
		fwrite($stream, 'unknown content');
		rewind($stream);

		// wrapSteam catches exceptions and doesn't propagate them
		// Exception handling depends on block_unreachable config
		$result = $wrappedStorage->wrapSteam('/files/test.txt', $stream, $scanner);
		$this->assertNotNull($result);
		// Consume stream to trigger scanning callbacks
		stream_get_contents($result);
		fclose($result);
	}

	public static function unreachableAVProvider(): array {
		return [
			'unreachable AV with block disabled' => [false, 'Upload allowed when unreachable'],
			'unreachable AV with block enabled' => [true, 'Upload blocked when unreachable'],
		];
	}

	/**
	 * Regression for the federated-share 500 (NoUserException): with the E2EE app
	 * enabled, shouldWrap() resolves the file owner. For a received federated share
	 * getOwner() returns a cloud id (uuid@remote), which is not a local user, so
	 * getUserFolder() used to throw and Sabre turned it into an HTTP 500 on every
	 * read/download. The owner must be guarded so we skip E2EE detection instead of
	 * throwing, and normal scanning still applies (fail toward scanning, not bypass).
	 */
	public function testShouldWrapFederatedOwnerDoesNotThrow(): void {
		$storage = new class([]) extends Temporary {
			public function getOwner(string $path): string|false {
				return 'uuid@remote.example';
			}
		};

		$userManager = $this->createMock(IUserManager::class);
		// A federated cloud id does not resolve to a local user.
		$userManager->method('get')->willReturn(null);

		$wrappedStorage = new AvirWrapper([
			'storage' => $storage,
			'scannerFactory' => $this->scannerFactory,
			'l10n' => $this->l10n,
			'logger' => $this->logger,
			'activityManager' => $this->createMock(IManager::class),
			'isHomeStorage' => true,
			'eventDispatcher' => $this->createMock(EventDispatcherInterface::class),
			'trashEnabled' => true,
			'groupFoldersEnabled' => false,
			'e2eeEnabled' => true,
			'blockListedDirectories' => [],
			'mount_point' => '/user/files/',
			'block_unscannable' => false,
			'userManager' => $userManager,
			'block_unreachable' => false,
			'request' => $this->createMock(IRequest::class),
		]);

		// Must not throw NoUserException, and scanning must still apply.
		self::assertTrue($wrappedStorage->shouldWrap('/files/shared.pdf'));
	}

	/**
	 * A local owner is still resolved through the E2EE detection branch, and a
	 * non-encrypted file still gets scanned (guarding the federated case must not
	 * disable scanning for local content).
	 */
	public function testShouldWrapLocalOwnerStillScans(): void {
		$storage = new class([]) extends Temporary {
			public function getOwner(string $path): string|false {
				return AvirWrapperTest::UID;
			}
		};

		$userManager = $this->createMock(IUserManager::class);
		$userManager->method('get')
			->with(self::UID)
			->willReturn($this->createMock(\OCP\IUser::class));

		$wrappedStorage = new AvirWrapper([
			'storage' => $storage,
			'scannerFactory' => $this->scannerFactory,
			'l10n' => $this->l10n,
			'logger' => $this->logger,
			'activityManager' => $this->createMock(IManager::class),
			'isHomeStorage' => true,
			'eventDispatcher' => $this->createMock(EventDispatcherInterface::class),
			'trashEnabled' => true,
			'groupFoldersEnabled' => false,
			'e2eeEnabled' => true,
			'blockListedDirectories' => [],
			'mount_point' => '/' . self::UID . '/files/',
			'block_unscannable' => false,
			'userManager' => $userManager,
			'block_unreachable' => false,
			'request' => $this->createMock(IRequest::class),
		]);

		// Local owner, non-encrypted node: scanning still applies.
		self::assertTrue($wrappedStorage->shouldWrap('/files/local.txt'));
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
			protected function handleConnectionError(string $path, bool $cleanup = false): void {
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
