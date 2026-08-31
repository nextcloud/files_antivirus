<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests\Listener;

use OC\Files\Storage\Wrapper\Jail;
use OCA\Files_Antivirus\AvirWrapper;
use OCA\Files_Antivirus\Listener\FilesystemSetupListener;
use OCA\GroupFolders\Mount\GroupFolderEncryptionJail;
use OCP\Files\Storage\ISharedStorage;
use OCP\Files\Storage\IStorage;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class FilesystemSetupListenerTest extends TestCase {
	public function testSharedStorageIsCheckedBeforeAvirWrapper(): void {
		$checkedClasses = [];
		$storage = $this->createMock(IStorage::class);
		$storage->method('instanceOfStorage')
			->willReturnCallback(function (string $class) use (&$checkedClasses): bool {
				$checkedClasses[] = $class;

				return match ($class) {
					Jail::class, ISharedStorage::class => true,
					AvirWrapper::class => self::fail('AvirWrapper must not be checked for shared storage'),
					default => false,
				};
			});

		self::assertTrue($this->shouldSkipWrapping($storage));
		self::assertSame([
			Jail::class,
			ISharedStorage::class,
		], $checkedClasses);
	}

	public function testWrappedJailIsSkipped(): void {
		$storage = $this->getStorageMock([
			Jail::class => true,
			ISharedStorage::class => false,
			AvirWrapper::class => true,
		]);

		self::assertTrue($this->shouldSkipWrapping($storage));
	}

	public function testUnwrappedJailIsNotSkipped(): void {
		$storage = $this->getStorageMock([
			Jail::class => true,
			ISharedStorage::class => false,
			AvirWrapper::class => false,
		]);

		self::assertFalse($this->shouldSkipWrapping($storage));
	}

	public function testEncryptedGroupFolderIsNotSkipped(): void {
		$storage = $this->getStorageMock([
			Jail::class => true,
			ISharedStorage::class => false,
			AvirWrapper::class => true,
			GroupFolderEncryptionJail::class => true,
		]);

		self::assertFalse($this->shouldSkipWrapping($storage, true));
	}

	/**
	 * @param array<class-string, bool> $storageTypes
	 */
	private function getStorageMock(array $storageTypes): IStorage&MockObject {
		$storage = $this->createMock(IStorage::class);
		$storage->method('instanceOfStorage')
			->willReturnCallback(fn (string $class): bool => $storageTypes[$class] ?? false);

		return $storage;
	}

	private function shouldSkipWrapping(IStorage $storage, bool $groupFolderEncryptionEnabled = false): bool {
		$reflection = new \ReflectionClass(FilesystemSetupListener::class);
		$listener = $reflection->newInstanceWithoutConstructor();
		$reflection->getProperty('groupFolderEncryptionEnabled')->setValue($listener, $groupFolderEncryptionEnabled);

		return $reflection->getMethod('shouldSkipWrapping')->invoke($listener, $storage);
	}
}
