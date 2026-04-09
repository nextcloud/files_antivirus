<?php

/**
 * SPDX-FileCopyrightText: 2017-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2015-2016 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests;

use OCA\Files_Antivirus\AppConfig;
use OCA\Files_Antivirus\AppInfo\Application;
use OCP\App\IAppManager;
use OCP\AppFramework\IAppContainer;
use OCP\IDBConnection;
use OCP\IL10N;
use OCP\Server;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Container\ContainerInterface;
use Test\TestCase;

abstract class TestBase extends TestCase {
	protected IDBConnection $db;
	protected Application $application;
	protected ContainerInterface $container;
	protected AppConfig&MockObject $config;
	protected IL10N&MockObject $l10n;

	protected function setUp(): void {
		parent::setUp();
		Server::get(IAppManager::class)->loadApp('files_antivirus');

		$this->db = Server::get(IDBConnection::class);

		$this->application = new Application();
		$this->container = $this->application->getContainer();

		$this->config = $this->getMockBuilder(AppConfig::class)
			->disableOriginalConstructor()
			->setMethods(['getAvPath', 'getAvChunkSize', 'getAvMode', 'getAppValue', 'getAvHost', 'getAvPort',  'getAvBlockUnscannable'])
			->getMock();

		$this->config->expects($this->any())
			->method('getAvPath')
			->will($this->returnValue(__DIR__ . '/avir.sh'));
		$this->config->expects($this->any())
			->method('getAvChunkSize')
			->will($this->returnValue(1024));
		$this->config->expects($this->any())
			->method('getAvMode')
			->will($this->returnValue('executable'));
		$this->config->expects($this->any())
			->method('getAppValue')
			->willReturnCallback(function ($methodName) {
				switch ($methodName) {
					case 'getAvPath':
						return  __DIR__ . '/avir.sh';
					case 'getAvMode':
						return 'executable';
				}
				return '';
			});
		$this->config->expects($this->any())
			->method('getAvHost')
			->will($this->returnValue('localhost'));
		$this->config->expects($this->any())
			->method('getAvPort')
			->will($this->returnValue('5555'));

		$this->l10n = $this->getMockBuilder(IL10N::class)
			->disableOriginalConstructor()
			->getMock();
		$this->l10n->method('t')->will($this->returnArgument(0));
	}
}
