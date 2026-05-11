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
	private NodeWrittenListener $listener;

	protected function setUp(): void {
		parent::setUp();
		$this->itemMapper = $this->createMock(ItemMapper::class);
		$this->timeFactory = $this->createMock(ITimeFactory::class);
		$this->logger = $this->createMock(LoggerInterface::class);

		$this->listener = new NodeWrittenListener(
			$this->itemMapper,
			$this->timeFactory,
			$this->logger,
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

	public function testMarksFileAsScanned(): void {
		$fileId = 42;
		$checkTime = 1234567890;

		$event = $this->createMock(NodeWrittenEvent::class);
		$file = $this->createMock(File::class);
		$file->method('getId')->willReturn($fileId);
		$event->method('getNode')->willReturn($file);

		$this->timeFactory->method('getTime')->willReturn($checkTime);

		// Simulate no existing entry
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

	public function testUpdatesExistingEntry(): void {
		$fileId = 42;
		$checkTime = 1234567890;

		$event = $this->createMock(NodeWrittenEvent::class);
		$file = $this->createMock(File::class);
		$file->method('getId')->willReturn($fileId);
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

	public function testHandlesInsertException(): void {
		$fileId = 42;

		$event = $this->createMock(NodeWrittenEvent::class);
		$file = $this->createMock(File::class);
		$file->method('getId')->willReturn($fileId);
		$event->method('getNode')->willReturn($file);

		$this->timeFactory->method('getTime')->willReturn(1234567890);

		$this->itemMapper->expects(self::once())
			->method('findByFileId')
			->with($fileId)
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

	/**
	 * SECURITY TEST: When scanner is unreachable, file should NOT be marked as scanned.
	 *
	 * Scenario: block_unreachable: false
	 * - AV scanner is unreachable/unavailable
	 * - Upload is allowed to proceed (config: block_unreachable: false)
	 * - File is written to disk
	 * - NodeWrittenEvent fires
	 *
	 * Expected behavior (CORRECT - future fix):
	 * - File must NOT be marked as scanned in database
	 * - Background scanner will check it on next run
	 * - This prevents infected files from being skipped if AV was temporarily unreachable
	 *
	 * Current behavior (BROKEN - THIS TEST DOCUMENTS THE BUG):
	 * - File IS marked as scanned unconditionally ❌
	 * - Background scanner will SKIP this file ❌
	 * - Infected file could remain undetected ❌
	 *
	 * This test documents the security issue.
	 * It will FAIL when the fix is implemented correctly.
	 * When that happens, update the test to verify file is NOT marked.
	 *
	 * @todo When static tracking is implemented, change this test to verify file is NOT marked
	 */
	public function testUnreachableAVCurrentlyMarksFileUncorrectly(): void {
		// This test documents INCORRECT behavior that needs fixing
		$fileId = 42;
		$checkTime = 1234567890;

		$event = $this->createMock(NodeWrittenEvent::class);
		$file = $this->createMock(File::class);
		$file->method('getId')->willReturn($fileId);
		$event->method('getNode')->willReturn($file);

		$this->timeFactory->method('getTime')->willReturn($checkTime);

		// When scanner is unreachable, current implementation still marks the file
		// This is the SECURITY BUG - file should NOT be marked
		$this->itemMapper->expects(self::once())
			->method('findByFileId')
			->with($fileId)
			->willThrowException(new DoesNotExistException(''));

		$this->itemMapper->expects(self::once())
			->method('insert')
			->with(self::callback(function (Item $item) use ($fileId, $checkTime) {
				return $item->getFileid() === $fileId && $item->getCheckTime() === $checkTime;
			}));

		$this->logger->expects(self::never())
			->method('warning');

		// File IS marked (WRONG), but should NOT be marked (CORRECT)
		$this->listener->handle($event);
	}

	/**
	 * IMPORTANT: This test documents a KNOWN ISSUE.
	 *
	 * The current implementation marks ALL uploaded files as scanned,
	 * regardless of whether the AV scanner actually ran or what result it returned.
	 *
	 * This is a SECURITY VULNERABILITY:
	 * - If AV is unreachable (block_unreachable: false), files are allowed but NOT scanned
	 * - They should NOT be marked as scanned so background scanner checks them
	 * - But NodeWrittenListener has no way to know if AV was unreachable vs actually scanned
	 *
	 * EXPECTED BEHAVIOR (not yet implemented):
	 * - Only files with CLEAN or (UNSCANNABLE + block_unscannable: false) should be marked
	 * - Files with UNCHECKED (unreachable), INFECTED should NOT be marked
	 * - AvirWrapper should track which files were successfully scanned
	 * - NodeWrittenListener should only mark files that were actually scanned
	 *
	 * @todo Implement scan status tracking mechanism
	 */
	public function testKnownIssueUnreachableAVMarkedAsScanned(): void {
		// This test passes but documents incorrect behavior
		$fileId = 42;
		$checkTime = 1234567890;

		$event = $this->createMock(NodeWrittenEvent::class);
		$file = $this->createMock(File::class);
		$file->method('getId')->willReturn($fileId);
		$event->method('getNode')->willReturn($file);

		$this->timeFactory->method('getTime')->willReturn($checkTime);

		// AV was unreachable - file should NOT be marked as scanned
		// But current implementation marks it anyway
		$this->itemMapper->expects(self::once())
			->method('findByFileId')
			->with($fileId)
			->willThrowException(new DoesNotExistException(''));

		$this->itemMapper->expects(self::once())
			->method('insert')
			->with(self::callback(function (Item $item) use ($fileId, $checkTime) {
				return $item->getFileid() === $fileId && $item->getCheckTime() === $checkTime;
			}));

		// File is marked as scanned even though AV never ran
		// This is the ISSUE - background scanner will skip this file
		$this->listener->handle($event);

		// TODO: Change this to verify file is NOT marked after implementing status tracking
	}
}
