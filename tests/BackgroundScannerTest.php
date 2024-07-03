<?php

/**
 * SPDX-FileCopyrightText: 2018-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2017 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests;

use OC\Files\Storage\Temporary;
use OCA\Files_Antivirus\AppConfig;
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
use OCP\IDBConnection;
use Psr\Log\LoggerInterface;
use Test\Traits\MountProviderTrait;
use Test\Traits\UserTrait;

/**
 * @group DB
 */
class BackgroundScannerTest extends TestBase {
	use UserTrait;
	use MountProviderTrait;

	/** @var Folder */
	private $homeDirectory;

	protected function setUp(): void {
		parent::setUp();

		$this->createUser("av", "av");
		$storage = new Temporary();
		$storage->mkdir('files');
		$storage->getScanner()->scan('');
		$this->registerMount("av", $storage, "av");

		$this->loginAsUser("av");
		/** @var IRootFolder $root */
		$root = \OC::$server->get(IRootFolder::class);
		$this->homeDirectory = $root->getUserFolder("av");
	}

	private function markAllScanned() {
		$now = time();
		/** @var IDBConnection $db */
		$db = \OC::$server->get(IDBConnection::class);

		$db->getQueryBuilder()->delete('files_antivirus')->execute();

		$query = $db->getQueryBuilder();
		$query->select('fileid')
			->from('filecache');
		$fileIds = $query->execute()->fetchAll(\PDO::FETCH_COLUMN);

		$query = $db->getQueryBuilder();
		$query->insert('files_antivirus')
			->values([
				'fileid' => $query->createParameter('fileid'),
				'check_time' => $now,
			]);
		foreach ($fileIds as $fileId) {
			$query->setParameter('fileid', $fileId);
			$query->execute();
		}
	}

	private function getBackgroundScanner(): BackgroundScanner {
		$scannerFactory = $this->createMock(ScannerFactory::class);
		$status = $this->getMockBuilder(Status::class)
			->disableOriginalConstructor()
			->onlyMethods(['getNumericStatus', 'getDetails'])->getMock();
		$status->method('getNumericStatus')->willReturn(Status::SCANRESULT_CLEAN);
		$status->method('getDetails')->willReturn("");
		$scanner = $this->createMock(IScanner::class);
		$scanner->method('scan')
			->willReturn($status);
		$scannerFactory->method('getScanner')
			->willReturn($scanner);
		return new BackgroundScanner(
			\OC::$server->get(ITimeFactory::class),
			$scannerFactory,
			\OC::$server->get(AppConfig::class),
			\OC::$server->get(IRootFolder::class),
			\OC::$server->get(LoggerInterface::class),
			\OC::$server->get(IDBConnection::class),
			\OC::$server->get(IMimeTypeLoader::class),
			\OC::$server->get(ItemFactory::class),
			\OC::$server->get(IUserMountCache::class),
			\OC::$server->get(IEventDispatcher::class),
			false
		);
	}

	private function updateScannedTime(int $fileId, int $time) {
		/** @var IDBConnection $db */
		$db = \OC::$server->get(IDBConnection::class);

		$query = $db->getQueryBuilder();
		$query->update('files_antivirus')
			->set('check_time', $query->createNamedParameter($time))
			->where($query->expr()->eq('fileid', $query->createNamedParameter($fileId)));
		$query->execute();
	}

	public function testGetUnscannedFiles() {
		$this->markAllScanned();

		$scanner = $this->getBackgroundScanner();
		$newFileId = $this->homeDirectory->newFile("foo", "bar")->getId();

		$outdated = iterator_to_array($scanner->getUnscannedFiles());
		$this->assertEquals([$newFileId], $outdated);
	}

	public function testGetOutdatedFiles() {
		$newFileId = $this->homeDirectory->newFile("foo", "bar")->getId();
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
		$newFileId = $this->homeDirectory->newFile("foo", "bar")->getId();

		$outdated = iterator_to_array($scanner->getUnscannedFiles());
		$this->assertEquals([$newFileId], $outdated);

		$scanner->scan(PHP_INT_MAX);

		$outdated = iterator_to_array($scanner->getUnscannedFiles());
		$this->assertEquals([], $outdated);
	}
}
