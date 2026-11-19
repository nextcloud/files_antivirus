<?php

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests;

use OCA\Files_Antivirus\AppInfo\ConfigLexicon;
use OCA\Files_Antivirus\AuditLog\Operation;
use OCA\Files_Antivirus\Db\ItemMapper;
use OCA\Files_Antivirus\Item;
use OCA\Files_Antivirus\Status;
use OCA\Files_Antivirus\Tests\AuditLog\AuditEvents;
use OCP\Activity\IManager as ActivityManager;
use OCP\App\IAppManager;
use OCP\AppFramework\Services\IAppConfig;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Files\File;
use OCP\Files\Folder;
use OCP\Files\IRootFolder;
use OCP\Files\IUserFolder;
use OCP\Files\NotPermittedException;
use OCP\IUser;
use OCP\Log\Audit\CriticalActionPerformedEvent;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class ItemTest extends TestCase {
	private File&MockObject $file;
	private ActivityManager&MockObject $activityManager;
	private IEventDispatcher&MockObject $eventDispatcher;
	private ItemMapper&MockObject $itemMapper;

	private function buildItem(?IUser $owner = null, string $infectedAction = 'only_log'): Item {
		$this->file = $this->createMock(File::class);
		$this->file->method('getId')->willReturn(42);
		$this->file->method('getPath')->willReturn('/cyprien/files/shared/test.docx');
		$this->file->method('getName')->willReturn('test.docx');
		$this->file->method('getUploadTime')->willReturn(0);
		// A received federated share has a remote owner that does not resolve
		// to a local user: Node::getOwner() returns null.
		$this->file->method('getOwner')->willReturn($owner);

		$this->activityManager = $this->createMock(ActivityManager::class);
		$this->eventDispatcher = $this->createMock(IEventDispatcher::class);
		$this->itemMapper = $this->createMock(ItemMapper::class);

		// IUserFolder only exists from Nextcloud 36, before that getUserFolder() returns a Folder
		$userFolder = $this->createMock(interface_exists(IUserFolder::class) ? IUserFolder::class : Folder::class);
		$userFolder->method('getRelativePath')->willReturn('/shared/test.docx');
		$rootFolder = $this->createMock(IRootFolder::class);
		$rootFolder->method('getUserFolder')->willReturn($userFolder);

		$config = $this->createMock(IAppConfig::class);
		$config->method('getAppValueString')
			->with(ConfigLexicon::AV_INFECTED_ACTION)
			->willReturn($infectedAction);

		return new Item(
			$config,
			$this->activityManager,
			$this->itemMapper,
			$this->createMock(LoggerInterface::class),
			$rootFolder,
			$this->createMock(IAppManager::class),
			$this->eventDispatcher,
			$this->file,
			$this->createMock(ITimeFactory::class),
			true,
		);
	}

	private function createStatus(int $numericStatus = Status::SCANRESULT_INFECTED): Status&MockObject {
		$status = $this->createMock(Status::class);
		$status->method('getDetails')->willReturn('Eicar-Test-Signature');
		$status->method('getNumericStatus')->willReturn($numericStatus);
		return $status;
	}

	private function expectAuditEvent(string $message, array $parameters): void {
		$this->eventDispatcher->expects($this->once())
			->method('dispatchTyped')
			->willReturnCallback(function (CriticalActionPerformedEvent $event) use ($message, $parameters): void {
				$this->assertTrue(AuditEvents::hasOperation($event, Operation::InfectedFileDetected->value));
				$this->assertSame($message, $event->getLogMessage());
				$this->assertSame($parameters, $event->getParameters());
			});
	}

	/**
	 * Regression for #614: the background scan logs the file being scanned via
	 * these helpers. With a federated (owner-less) file they used to call
	 * getOwner()->getUID() and crash the whole scan run.
	 */
	public function testLogHelpersSurviveNullOwner(): void {
		$item = $this->buildItem();

		$item->logDebug('scanning');
		$item->logNotice('scanning');
		$item->logError('scanning');

		// No TypeError / "getUID() on null": reaching here is the assertion.
		$this->addToAssertionCount(1);
	}

	/**
	 * An infected federated file has no local user to attribute activity to,
	 * so publishing is skipped rather than crashing on getOwner()->getUID().
	 */
	public function testProcessInfectedSkipsActivityForNullOwner(): void {
		$item = $this->buildItem();

		// Nothing to attribute: no activity event should be published.
		$this->activityManager->expects($this->never())->method('publish');

		$status = $this->createMock(\OCA\Files_Antivirus\Status::class);
		$status->method('getDetails')->willReturn('Eicar-Test-Signature');

		$item->processInfected($status);
	}

	public function testProcessInfectedLogsDeletedFile(): void {
		$owner = $this->createMock(IUser::class);
		$owner->method('getUID')->willReturn('alice');
		$item = $this->buildItem($owner, 'delete');

		$this->file->expects($this->once())->method('delete');
		$this->expectAuditEvent('Infected file %s of "%s" was deleted', [
			'fileId' => 42,
			'ownerId' => 'alice',
			'details' => 'Eicar-Test-Signature',
			'unscannable' => false,
			'infectedAction' => 'delete',
		]);

		$item->processInfected($this->createStatus());
	}

	public function testProcessInfectedLogsFoundFile(): void {
		$item = $this->buildItem(null, 'only_log');

		$this->file->expects($this->never())->method('delete');
		$this->itemMapper->expects($this->once())->method('insert');
		$this->expectAuditEvent('Infected file %s of "%s" was found', [
			'fileId' => 42,
			'ownerId' => null,
			'details' => 'Eicar-Test-Signature',
			'unscannable' => true,
			'infectedAction' => 'only_log',
		]);

		$item->processInfected($this->createStatus(Status::SCANRESULT_UNSCANNABLE));
	}

	public function testProcessInfectedFailedDeleteIsNotLogged(): void {
		$item = $this->buildItem(null, 'delete');

		$this->file->method('delete')->willThrowException(new NotPermittedException());
		$this->eventDispatcher->expects($this->never())->method('dispatchTyped');

		$this->expectException(NotPermittedException::class);
		$item->processInfected($this->createStatus());
	}

	public function testProcessCleanIsNotLogged(): void {
		$item = $this->buildItem();

		$this->eventDispatcher->expects($this->never())->method('dispatchTyped');

		$item->processClean();
	}
}
