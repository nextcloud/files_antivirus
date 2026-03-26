<?php

/**
 * SPDX-FileCopyrightText: 2018-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2017 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests;

use OC\Files\Storage\Temporary;
use OCA\Files_Antivirus\BackgroundJob\BackgroundScanner;
use OCA\Files_Antivirus\ItemFactory;
use OCA\Files_Antivirus\Scanner\IScanner;
use OCA\Files_Antivirus\Scanner\ScannerFactory;
use OCA\Files_Antivirus\Status;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Files\Config\IUserMountCache;
use OCP\Files\Folder;
use OCP\Files\IMimeTypeLoader;
use OCP\Files\IRootFolder;
use OCP\IConfig;
use OCP\IDBConnection;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;
use Test\Traits\MountProviderTrait;
use Test\Traits\UserTrait;

#[Group('DB')]
class BackgroundScannerTest extends TestBase {
	use UserTrait;
	use MountProviderTrait;

	private Folder $homeDirectory;
	private Folder $externalDirectory;

	protected function setUp(): void {
		parent::setUp();

		$this->createUser('av', 'av');
		$storage = new TemporaryHome();
		$storage->mkdir('files');
		$storage->getScanner()->scan('');

		$external = new Temporary();
		$external->getScanner()->scan('');

		$this->registerMount('av', $storage, 'av');
		$this->registerMount('av', $external, 'av/files/external');

		$this->loginAsUser('av');
		$root = Server::get(IRootFolder::class);
		$this->homeDirectory = $root->getUserFolder('av');
		$this->externalDirectory = $this->homeDirectory->get('external');
	}

	private function markAllScanned() {
		$now = time();
		$db = Server::get(IDBConnection::class);

		$db->getQueryBuilder()->delete('files_antivirus')->executeStatement();

		$query = $db->getQueryBuilder();
		$query->select('fileid')
			->from('filecache');
		$fileIds = $query->executeQuery()->fetchAll(\PDO::FETCH_COLUMN);

		$query = $db->getQueryBuilder();
		$query->insert('files_antivirus')
			->values([
				'fileid' => $query->createParameter('fileid'),
				'check_time' => $now,
			]);
		foreach ($fileIds as $fileId) {
			$query->setParameter('fileid', $fileId);
			$query->executeStatement();
		}
	}

	private function getBackgroundScanner(): BackgroundScanner {
		$scannerFactory = $this->createMock(ScannerFactory::class);
		$status = $this->getMockBuilder(Status::class)
			->disableOriginalConstructor()
			->onlyMethods(['getNumericStatus', 'getDetails'])->getMock();
		$status->method('getNumericStatus')->willReturn(Status::SCANRESULT_CLEAN);
		$status->method('getDetails')->willReturn('');
		$scanner = $this->createMock(IScanner::class);
		$scanner->method('scan')
			->willReturn($status);
		$scannerFactory->method('getScanner')
			->willReturn($scanner);
		return new BackgroundScanner(
			Server::get(ITimeFactory::class),
			$scannerFactory,
			$this->config,
			Server::get(IRootFolder::class),
			Server::get(LoggerInterface::class),
			Server::get(IDBConnection::class),
			Server::get(IMimeTypeLoader::class),
			Server::get(ItemFactory::class),
			Server::get(IUserMountCache::class),
			Server::get(IEventDispatcher::class),
			Server::get(IConfig::class),
			false
		);
	}

	private function updateScannedTime(int $fileId, int $time) {
		$db = Server::get(IDBConnection::class);

		$query = $db->getQueryBuilder();
		$query->update('files_antivirus')
			->set('check_time', $query->createNamedParameter($time))
			->where($query->expr()->eq('fileid', $query->createNamedParameter($fileId)));
		$query->executeStatement();
	}

	public function testGetUnscannedFiles() {
		$this->markAllScanned();

		$scanner = $this->getBackgroundScanner();
		$newFileId = $this->homeDirectory->newFile('foo', 'bar')->getId();
		$this->homeDirectory->getParent()->newFile('outside', 'bar')->getId();

		$outdated = iterator_to_array($scanner->getUnscannedFiles());
		$this->assertEquals([$newFileId], $outdated);
	}

	public function testGetUnscannedFilesExternal() {
		$this->markAllScanned();

		$scanner = $this->getBackgroundScanner();
		$newFileId = $this->homeDirectory->newFile('external/foo2', 'bar2')->getId();

		$outdated = iterator_to_array($scanner->getUnscannedFiles());
		$this->assertEquals([$newFileId], $outdated);
	}

	public function testGetOutdatedFiles() {
		$newFileId = $this->homeDirectory->newFile('foo', 'bar')->getId();
		$this->markAllScanned();

		$scanner = $this->getBackgroundScanner();

		$outdated = iterator_to_array($scanner->getOutdatedFiles());
		$this->assertEquals([], $outdated);

		$this->updateScannedTime($newFileId, time() - (30 * 24 * 60 * 60));
		$outdated = iterator_to_array($scanner->getOutdatedFiles());
		$this->assertEquals([$newFileId], $outdated);
	}

	public function testTestScanFiles() {
		$this->markAllScanned();

		$scanner = $this->getBackgroundScanner();
		$newFileId = $this->homeDirectory->newFile('foo', 'bar')->getId();

		$outdated = iterator_to_array($scanner->getUnscannedFiles());
		$this->assertEquals([$newFileId], $outdated);

		$scanner->scan(PHP_INT_MAX);

		$outdated = iterator_to_array($scanner->getUnscannedFiles());
		$this->assertEquals([], $outdated);
	}
}
