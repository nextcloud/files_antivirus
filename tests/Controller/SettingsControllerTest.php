<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests\Controller;

use OCA\Files_Antivirus\AppInfo\ConfigLexicon;
use OCA\Files_Antivirus\AuditLog\Operation;
use OCA\Files_Antivirus\Controller\SettingsController;
use OCA\Files_Antivirus\Scanner\IScanner;
use OCA\Files_Antivirus\Scanner\ScannerFactory;
use OCA\Files_Antivirus\Status;
use OCA\Files_Antivirus\Tests\AuditLog\AuditEvents;
use OCP\AppFramework\Http;
use OCP\AppFramework\Services\IAppConfig;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IL10N;
use OCP\IRequest;
use OCP\Log\Audit\CriticalActionPerformedEvent;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class SettingsControllerTest extends TestCase {
	private IAppConfig&MockObject $appConfig;
	private ScannerFactory&MockObject $scannerFactory;
	private ConfigLexicon&MockObject $configLexicon;
	private IEventDispatcher&MockObject $eventDispatcher;
	private SettingsController $controller;

	protected function setUp(): void {
		parent::setUp();

		$this->appConfig = $this->createMock(IAppConfig::class);
		$this->scannerFactory = $this->createMock(ScannerFactory::class);
		$this->configLexicon = $this->createMock(ConfigLexicon::class);
		$this->eventDispatcher = $this->createMock(IEventDispatcher::class);
		$l10n = $this->createMock(IL10N::class);
		$l10n->method('t')->willReturnArgument(0);

		$this->controller = new SettingsController(
			'files_antivirus',
			$this->createMock(IRequest::class),
			$this->appConfig,
			$l10n,
			$this->scannerFactory,
			$this->configLexicon,
			$this->eventDispatcher,
		);
	}

	private function save(array $cmdOptions = ['--fdpass']): Http\JSONResponse {
		return $this->controller->save(
			'daemon',
			'/var/run/clamav/clamd.ctl',
			'clamav.example.com',
			3310,
			$cmdOptions,
			'/usr/bin/clamscan',
			'delete',
			1048576,
			-1,
			-1,
			true,
			false,
			false,
			'',
			'',
			'',
		);
	}

	public function testSaveLogsSettings(): void {
		$status = $this->createMock(Status::class);
		$status->method('getNumericStatus')->willReturn(Status::SCANRESULT_CLEAN);
		$scanner = $this->createMock(IScanner::class);
		$scanner->method('scanString')->willReturn($status);
		$this->scannerFactory->method('getScanner')->willReturn($scanner);

		$this->appConfig->expects($this->atLeastOnce())->method('setAppValueString');
		$this->eventDispatcher->expects($this->once())
			->method('dispatchTyped')
			->willReturnCallback(function (CriticalActionPerformedEvent $event): void {
				$this->assertTrue(AuditEvents::hasOperation($event, Operation::SettingsUpdated->value));
				$this->assertSame('Antivirus settings were changed, mode: "%s", action on infected files: "%s"', $event->getLogMessage());
				$this->assertSame([
					'avMode' => 'daemon',
					'avInfectedAction' => 'delete',
					'avBlockUnscannable' => false,
					'avBlockUnreachable' => true,
				], $event->getParameters());
			});

		$this->save();
	}

	public function testSaveLogsSettingsWhenSelfTestFails(): void {
		$this->scannerFactory->method('getScanner')->willThrowException(new \Exception('No connection'));

		$this->eventDispatcher->expects($this->once())
			->method('dispatchTyped')
			->with($this->isInstanceOf(CriticalActionPerformedEvent::class));

		$response = $this->save();

		$this->assertSame('error', $response->getData()['status']);
	}

	public function testSaveDoesNotLogInvalidSettings(): void {
		$this->appConfig->expects($this->never())->method('setAppValueString');
		$this->eventDispatcher->expects($this->never())->method('dispatchTyped');

		$response = $this->save([1]);

		$this->assertSame(Http::STATUS_BAD_REQUEST, $response->getStatus());
	}
}
