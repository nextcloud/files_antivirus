<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests\Command;

use OCA\Files_Antivirus\AuditLog\Operation;
use OCA\Files_Antivirus\Command\Mark;
use OCA\Files_Antivirus\Item;
use OCA\Files_Antivirus\ItemFactory;
use OCA\Files_Antivirus\Tests\AuditLog\AuditEvents;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Files\File;
use OCP\Files\Folder;
use OCP\Files\IRootFolder;
use OCP\Log\Audit\CriticalActionPerformedEvent;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\Console\Tester\CommandTester;
use Test\TestCase;

class MarkTest extends TestCase {
	private IRootFolder&MockObject $rootFolder;
	private Item&MockObject $item;
	private IEventDispatcher&MockObject $eventDispatcher;
	private CommandTester $commandTester;

	protected function setUp(): void {
		parent::setUp();

		$this->rootFolder = $this->createMock(IRootFolder::class);
		$this->item = $this->createMock(Item::class);
		$itemFactory = $this->createMock(ItemFactory::class);
		$itemFactory->method('newItem')->willReturn($this->item);
		$this->eventDispatcher = $this->createMock(IEventDispatcher::class);

		$this->commandTester = new CommandTester(new Mark($this->rootFolder, $itemFactory, $this->eventDispatcher));
	}

	public static function dataMark(): array {
		return [
			'scanned' => ['scanned', false, 'processClean', false],
			'scanned forever' => ['scanned', true, 'updateCheckTime', true],
			'unscanned' => ['unscanned', false, 'removeCheckTime', false],
			'unscanned ignores forever' => ['unscanned', true, 'removeCheckTime', false],
		];
	}

	#[DataProvider('dataMark')]
	public function testMark(string $mode, bool $forever, string $itemMethod, bool $loggedForever): void {
		$file = $this->createMock(File::class);
		$file->method('getId')->willReturn(42);
		$this->rootFolder->method('get')->with('/alice/files/test.txt')->willReturn($file);

		$this->item->expects($this->once())->method($itemMethod);
		$this->eventDispatcher->expects($this->once())
			->method('dispatchTyped')
			->willReturnCallback(function (CriticalActionPerformedEvent $event) use ($mode, $loggedForever): void {
				$this->assertTrue(AuditEvents::hasOperation($event, Operation::ScanStateUpdated->value));
				$this->assertSame('File %s was marked as %s for the antivirus scan', $event->getLogMessage());
				$this->assertSame([
					'fileId' => 42,
					'mode' => $mode,
					'forever' => $loggedForever,
				], $event->getParameters());
			});

		$exitCode = $this->commandTester->execute([
			'file' => '/alice/files/test.txt',
			'mode' => $mode,
			'--forever' => $forever,
		]);

		$this->assertSame(0, $exitCode);
	}

	public function testInvalidModeIsNotLogged(): void {
		$this->rootFolder->method('get')->willReturn($this->createMock(File::class));
		$this->eventDispatcher->expects($this->never())->method('dispatchTyped');

		$exitCode = $this->commandTester->execute(['file' => '/alice/files/test.txt', 'mode' => 'clean']);

		$this->assertSame(1, $exitCode);
	}

	public function testFolderIsNotLogged(): void {
		$this->rootFolder->method('get')->willReturn($this->createMock(Folder::class));
		$this->eventDispatcher->expects($this->never())->method('dispatchTyped');

		$exitCode = $this->commandTester->execute(['file' => '/alice/files', 'mode' => 'scanned']);

		$this->assertSame(1, $exitCode);
	}
}
