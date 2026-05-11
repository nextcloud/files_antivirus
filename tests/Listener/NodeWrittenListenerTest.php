<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests\Listener;

use OCA\Files_Antivirus\Db\Item;
use OCA\Files_Antivirus\Db\ItemMapper;
use OCA\Files_Antivirus\Listener\NodeWrittenListener;
use OCA\Files_Antivirus\ScannedPathsRegistry;
use OCA\Files_Antivirus\Status;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\Event;
use OCP\Files\Events\Node\NodeWrittenEvent;
use OCP\Files\File;
use OCP\Files\Folder;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use Test\TestCase;

#[Group('DB')]
class NodeWrittenListenerTest extends TestCase {
	private ItemMapper&MockObject $itemMapper;
	private ITimeFactory&MockObject $timeFactory;
	private LoggerInterface&MockObject $logger;
	private ScannedPathsRegistry $registry;
	private NodeWrittenListener $listener;

	protected function setUp(): void {
		parent::setUp();
		$this->itemMapper = $this->createMock(ItemMapper::class);
		$this->timeFactory = $this->createMock(ITimeFactory::class);
		$this->logger = $this->createMock(LoggerInterface::class);
		$this->registry = new ScannedPathsRegistry();

		$this->listener = new NodeWrittenListener(
			$this->itemMapper,
			$this->timeFactory,
			$this->logger,
			$this->registry,
		);
	}

	public function testIgnoresNonNodeWrittenEvent(): void {
		$event = $this->createMock(Event::class);
		$this->itemMapper->expects(self::never())->method('findByFileId');
		$this->listener->handle($event);
	}

	public function testIgnoresFolders(): void {
		$event = $this->createMock(NodeWrittenEvent::class);
		$folder = $this->createMock(Folder::class);
		$event->method('getNode')->willReturn($folder);

		$this->itemMapper->expects(self::never())->method('findByFileId');
		$this->listener->handle($event);
	}

	public function testMarksFileAsScannedWhenClean(): void {
		$fileId = 42;
		$filePath = '/admin/files/foo.txt';
		$checkTime = 1234567890;

		$this->registry->registerResult($filePath, Status::SCANRESULT_CLEAN);

		$event = $this->createMock(NodeWrittenEvent::class);
		$file = $this->createMock(File::class);
		$file->method('getId')->willReturn($fileId);
		$file->method('getPath')->willReturn($filePath);
		$event->method('getNode')->willReturn($file);

		$this->timeFactory->method('getTime')->willReturn($checkTime);

		$this->itemMapper->expects(self::once())
			->method('findByFileId')
			->with($fileId)
			->willThrowException(new DoesNotExistException(''));

		$this->itemMapper->expects(self::once())
			->method('insert')
			->with(self::callback(function (Item $item) use ($fileId, $checkTime) {
				return $item->getFileid() === $fileId && $item->getCheckTime() === $checkTime;
			}));

		$this->logger->expects(self::never())->method('warning');

		$this->listener->handle($event);
	}

	public function testMarksFileAsScannedWhenUnscannable(): void {
		$fileId = 42;
		$filePath = '/admin/files/foo.zip';
		$checkTime = 1234567890;

		$this->registry->registerResult($filePath, Status::SCANRESULT_UNSCANNABLE);

		$event = $this->createMock(NodeWrittenEvent::class);
		$file = $this->createMock(File::class);
		$file->method('getId')->willReturn($fileId);
		$file->method('getPath')->willReturn($filePath);
		$event->method('getNode')->willReturn($file);

		$this->timeFactory->method('getTime')->willReturn($checkTime);

		$this->itemMapper->expects(self::once())
			->method('findByFileId')
			->with($fileId)
			->willThrowException(new DoesNotExistException(''));

		$this->itemMapper->expects(self::once())
			->method('insert');

		$this->listener->handle($event);
	}

	public function testUpdatesExistingEntry(): void {
		$fileId = 42;
		$filePath = '/admin/files/foo.txt';
		$checkTime = 1234567890;

		$this->registry->registerResult($filePath, Status::SCANRESULT_CLEAN);

		$event = $this->createMock(NodeWrittenEvent::class);
		$file = $this->createMock(File::class);
		$file->method('getId')->willReturn($fileId);
		$file->method('getPath')->willReturn($filePath);
		$event->method('getNode')->willReturn($file);

		$this->timeFactory->method('getTime')->willReturn($checkTime);

		$existingItem = new Item();
		$existingItem->setFileid($fileId);
		$existingItem->setCheckTime(999);

		$this->itemMapper->expects(self::once())
			->method('findByFileId')
			->with($fileId)
			->willReturn($existingItem);

		$this->itemMapper->expects(self::once())
			->method('delete')
			->with($existingItem);

		$this->itemMapper->expects(self::once())
			->method('insert')
			->with(self::callback(function (Item $item) use ($fileId, $checkTime) {
				return $item->getFileid() === $fileId && $item->getCheckTime() === $checkTime;
			}));

		$this->logger->expects(self::never())->method('warning');

		$this->listener->handle($event);
	}

	public function testDoesNotMarkFileWhenAVUnreachable(): void {
		// When the scanner is unreachable and block_unreachable is false, the upload is
		// allowed but AvirWrapper does NOT register a result. The listener must NOT mark
		// the file so the background scanner can check it later.
		$event = $this->createMock(NodeWrittenEvent::class);
		$file = $this->createMock(File::class);
		$file->method('getId')->willReturn(42);
		$file->method('getPath')->willReturn('/admin/files/foo.txt');
		$event->method('getNode')->willReturn($file);

		// Registry is empty — no scan result was recorded by AvirWrapper
		$this->itemMapper->expects(self::never())->method('findByFileId');
		$this->itemMapper->expects(self::never())->method('insert');

		$this->listener->handle($event);
	}

	public function testDoesNotMarkFileWhenNotScanned(): void {
		// Files that bypass shouldWrap() (e.g. E2EE, blocklisted dirs) are never
		// registered in the registry, so the listener must leave them unmarked.
		$event = $this->createMock(NodeWrittenEvent::class);
		$file = $this->createMock(File::class);
		$file->method('getId')->willReturn(99);
		$file->method('getPath')->willReturn('/admin/files/encrypted.txt');
		$event->method('getNode')->willReturn($file);

		$this->itemMapper->expects(self::never())->method('findByFileId');
		$this->itemMapper->expects(self::never())->method('insert');

		$this->listener->handle($event);
	}

	public function testHandlesInsertException(): void {
		$fileId = 42;
		$filePath = '/admin/files/foo.txt';

		$this->registry->registerResult($filePath, Status::SCANRESULT_CLEAN);

		$event = $this->createMock(NodeWrittenEvent::class);
		$file = $this->createMock(File::class);
		$file->method('getId')->willReturn($fileId);
		$file->method('getPath')->willReturn($filePath);
		$event->method('getNode')->willReturn($file);

		$this->timeFactory->method('getTime')->willReturn(1234567890);

		$this->itemMapper->expects(self::once())
			->method('findByFileId')
			->willThrowException(new DoesNotExistException(''));

		$exception = new \Exception('DB error');
		$this->itemMapper->expects(self::once())
			->method('insert')
			->willThrowException($exception);

		$this->logger->expects(self::once())
			->method('warning')
			->with(self::stringContains('DB error'));

		$this->listener->handle($event);
	}
}
