<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests;

use OC\Files\Storage\Temporary;
use OCA\Files_Antivirus\AuditLog\Operation;
use OCA\Files_Antivirus\AvirWrapper;
use OCA\Files_Antivirus\ScannedPathsRegistry;
use OCA\Files_Antivirus\Scanner\IScanner;
use OCA\Files_Antivirus\Scanner\ScannerFactory;
use OCA\Files_Antivirus\Status;
use OCA\Files_Antivirus\Tests\AuditLog\AuditEvents;
use OCP\Activity\IEvent;
use OCP\Activity\IManager;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Files\InvalidContentException;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUserManager;
use OCP\Log\Audit\CriticalActionPerformedEvent;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class AvirWrapperAuditLogTest extends TestCase {
	private IEventDispatcher&MockObject $eventDispatcher;
	private Temporary&MockObject $storage;

	private function buildWrapper(int $numericStatus, bool $blockUnscannable = false): AvirWrapper {
		$status = $this->createMock(Status::class);
		$status->method('getNumericStatus')->willReturn($numericStatus);
		$status->method('getDetails')->willReturn('Eicar-Test-Signature');
		$scanner = $this->createMock(IScanner::class);
		$scanner->method('scanString')->willReturn($status);
		$scannerFactory = $this->createMock(ScannerFactory::class);
		$scannerFactory->method('getScanner')->willReturn($scanner);

		$activity = $this->createMock(IEvent::class);
		$activity->method($this->anything())->willReturnSelf();
		$activityManager = $this->createMock(IManager::class);
		$activityManager->method('generateEvent')->willReturn($activity);

		$l10n = $this->createMock(IL10N::class);
		$l10n->method('t')->willReturnArgument(0);

		$this->eventDispatcher = $this->createMock(IEventDispatcher::class);

		$this->storage = $this->createMock(Temporary::class);
		$this->storage->method('getOwner')->willReturn('alice');

		return new AvirWrapper([
			'storage' => $this->storage,
			'scannerFactory' => $scannerFactory,
			'l10n' => $l10n,
			'logger' => $this->createMock(LoggerInterface::class),
			'activityManager' => $activityManager,
			'isHomeStorage' => true,
			'eventDispatcher' => $this->eventDispatcher,
			'trashEnabled' => false,
			'groupFoldersEnabled' => false,
			'e2eeEnabled' => false,
			'blockListedDirectories' => [],
			'mount_point' => '/alice/',
			'block_unscannable' => $blockUnscannable,
			'userManager' => $this->createMock(IUserManager::class),
			'block_unreachable' => false,
			'request' => $this->createMock(IRequest::class),
			'scannedPathsRegistry' => new ScannedPathsRegistry(),
		]);
	}

	public static function dataBlockedUploads(): array {
		return [
			'infected' => [Status::SCANRESULT_INFECTED, false],
			'unscannable' => [Status::SCANRESULT_UNSCANNABLE, true],
		];
	}

	#[DataProvider('dataBlockedUploads')]
	public function testBlockedUploadIsLogged(int $numericStatus, bool $unscannable): void {
		$wrapper = $this->buildWrapper($numericStatus, true);

		$this->eventDispatcher->expects($this->once())
			->method('dispatchTyped')
			->willReturnCallback(function (CriticalActionPerformedEvent $event) use ($unscannable): void {
				$this->assertTrue(AuditEvents::hasOperation($event, Operation::InfectedUploadBlocked->value));
				$this->assertSame('Upload of infected file "%s" of "%s" was blocked', $event->getLogMessage());
				$this->assertSame([
					'path' => '/alice/files/virus.txt',
					'ownerId' => 'alice',
					'details' => 'Eicar-Test-Signature',
					'unscannable' => $unscannable,
				], $event->getParameters());
			});

		$this->storage->expects($this->once())->method('unlink')->with('files/virus.txt');
		$this->storage->expects($this->never())->method('file_put_contents');

		$this->expectException(InvalidContentException::class);
		$wrapper->file_put_contents('files/virus.txt', 'infected content');
	}

	public function testCleanUploadIsNotLogged(): void {
		$wrapper = $this->buildWrapper(Status::SCANRESULT_CLEAN);

		$this->eventDispatcher->expects($this->never())->method('dispatchTyped');

		$wrapper->file_put_contents('files/clean.txt', 'clean content');
	}

	public function testAllowedUnscannableUploadIsNotLogged(): void {
		$wrapper = $this->buildWrapper(Status::SCANRESULT_UNSCANNABLE, false);

		$this->eventDispatcher->expects($this->never())->method('dispatchTyped');

		$wrapper->file_put_contents('files/archive.zip', 'encrypted content');
	}
}
