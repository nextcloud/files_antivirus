<?php

/**
 * Copyright (c) 2017 Victor Dubiniuk <dubiniuk@owncloud.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */


namespace OCA\Files_Antivirus\Tests;

use OC\Files\Storage\Temporary;
use OCA\Files_Antivirus\BackgroundJob\BackgroundScanner;
use OCP\Files\Folder;
use OCP\Files\IRootFolder;
use OCP\IDBConnection;
use Test\Traits\MountProviderTrait;
use Test\Traits\UserTrait;

/**
 * @group DB
 */
class BackgroundScannerTest extends TestBase {
	use UserTrait;
	use MountProviderTrait;

	private Folder $homeDirectory;
	private Folder $externalDirectory;

	protected function setUp(): void {
		parent::setUp();

		$this->createUser("av", "av");
		$storage = new TemporaryHome();
		$storage->mkdir('files');
		$storage->getScanner()->scan('');

		$external = new Temporary();
		$external->getScanner()->scan('');

		$this->registerMount("av", $storage, "av");
		$this->registerMount("av", $external, "av/files/external");

		$this->loginAsUser("av");
		/** @var IRootFolder $root */
		$root = \OC::$server->get(IRootFolder::class);
		$this->homeDirectory = $root->getUserFolder("av");
		$this->externalDirectory = $this->homeDirectory->get('external');
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

		/** @var BackgroundScanner $scanner */
		$scanner = \OC::$server->get(BackgroundScanner::class);
		$newFileId = $this->homeDirectory->newFile("foo", "bar")->getId();
		$this->homeDirectory->getParent()->newFile("outside", "bar")->getId();

		$outdated = $scanner->getUnscannedFiles()->fetchAll(\PDO::FETCH_COLUMN);
		$this->assertEquals([$newFileId], $outdated);
	}

	public function testGetUnscannedFilesExternal() {
		$this->markAllScanned();

		/** @var BackgroundScanner $scanner */
		$scanner = \OC::$server->get(BackgroundScanner::class);
		$newFileId = $this->homeDirectory->newFile("external/foo2", "bar2")->getId();

		$outdated = $scanner->getUnscannedFiles()->fetchAll(\PDO::FETCH_COLUMN);
		$this->assertEquals([$newFileId], $outdated);
	}

	public function testGetOutdatedFiles() {
		$newFileId = $this->homeDirectory->newFile("foo", "bar")->getId();
		$this->markAllScanned();

		/** @var BackgroundScanner $scanner */
		$scanner = \OC::$server->get(BackgroundScanner::class);

		$outdated = $scanner->getOutdatedFiles()->fetchAll(\PDO::FETCH_COLUMN);
		$this->assertEquals([], $outdated);

		$this->updateScannedTime($newFileId, time() - (30 * 24 * 60 * 60));
		$outdated = $scanner->getOutdatedFiles()->fetchAll(\PDO::FETCH_COLUMN);
		$this->assertEquals([$newFileId], $outdated);
	}
}
