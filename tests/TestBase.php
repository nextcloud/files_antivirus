<?php

/**
 * SPDX-FileCopyrightText: 2017-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2015-2016 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests;

use OCA\Files_Antivirus\AppInfo\Application;
use OCA\Files_Antivirus\AppInfo\ConfigLexicon;
use OCP\App\IAppManager;
use OCP\AppFramework\IAppContainer;
use OCP\AppFramework\Services\IAppConfig;
use OCP\IDBConnection;
use OCP\IL10N;
use OCP\Server;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

abstract class TestBase extends TestCase {
	protected IDBConnection $db;
	protected Application $application;
	protected IAppContainer $container;
	protected IAppConfig&MockObject $config;
	protected IL10N&MockObject $l10n;


	protected function setUp(): void {
		parent::setUp();

		Server::get(IAppManager::class)->loadApp(Application::APP_NAME);
		Server::get(\OCP\IAppConfig::class)->setValueBool(
			Application::APP_NAME,
			ConfigLexicon::AV_BLOCK_UNREACHABLE,
			false,
		);

		$this->db = Server::get(IDBConnection::class);
		$this->application = new Application();
		$this->container = $this->application->getContainer();

		$this->config = $this->createMock(IAppConfig::class);
		$this->config->expects($this->any())
			->method('getAppValueString')
			->willReturnCallback($this->getAppValue(...));
		$this->config->expects($this->any())
			->method('getAppValueInt')
			->willReturnCallback($this->getAppValue(...));
		$this->config->expects($this->any())
			->method('getAppValueBool')
			->willReturnCallback($this->getAppValue(...));

		$this->l10n = $this->createMock(IL10N::class);
		$this->l10n->method('t')->will($this->returnArgument(0));
	}

	public function getAppValue($methodName) {
		switch ($methodName) {
			case ConfigLexicon::AV_PATH:
				return  __DIR__ . '/avir.sh';
			case ConfigLexicon::AV_MODE:
				return 'executable';
			case ConfigLexicon::AV_ICAP_CHUNK_SIZE:
				return 1024;
			case ConfigLexicon::AV_MAX_FILE_SIZE:
				return 10 * 1024 * 1024;
			case ConfigLexicon::AV_HOST:
				return 'localhost';
			case ConfigLexicon::AV_PORT:
				return 5555;
			case ConfigLexicon::AV_BLOCK_UNREACHABLE:
				return true;
			case ConfigLexicon::AV_BLOCK_UNSCANNABLE:
				return false;
		}
	}
}
