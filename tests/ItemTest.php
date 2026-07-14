<?php

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests;

use OCA\Files_Antivirus\Db\ItemMapper;
use OCA\Files_Antivirus\Item;
use OCP\Activity\IManager as ActivityManager;
use OCP\App\IAppManager;
use OCP\AppFramework\Services\IAppConfig;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Files\File;
use OCP\Files\IRootFolder;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class ItemTest extends TestCase {
	private File&MockObject $file;
	private ActivityManager&MockObject $activityManager;

	private function buildItem(): Item {
		$this->file = $this->createMock(File::class);
		$this->file->method('getId')->willReturn(42);
		$this->file->method('getPath')->willReturn('/cyprien/files/shared/test.docx');
		$this->file->method('getName')->willReturn('test.docx');
		$this->file->method('getUploadTime')->willReturn(0);
		// A received federated share has a remote owner that does not resolve
		// to a local user: Node::getOwner() returns null.
		$this->file->method('getOwner')->willReturn(null);

		$this->activityManager = $this->createMock(ActivityManager::class);

		return new Item(
			$this->createMock(IAppConfig::class),
			$this->activityManager,
			$this->createMock(ItemMapper::class),
			$this->createMock(LoggerInterface::class),
			$this->createMock(IRootFolder::class),
			$this->createMock(IAppManager::class),
			$this->file,
			$this->createMock(ITimeFactory::class),
			true,
		);
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
}
