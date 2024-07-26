<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2022 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests\Db;

use OCA\Files_Antivirus\Db\Item;
use OCA\Files_Antivirus\Db\ItemMapper;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\IDBConnection;
use Test\TestCase;

/**
 * @group DB
 */
class ItemMapperTest extends TestCase {
	private ItemMapper $itemMapper;

	protected function setUp(): void {
		parent::setUp();

		$this->itemMapper = new ItemMapper(\OC::$server->get(IDBConnection::class));
	}

	public function testGetNonExisting() {
		$this->expectException(DoesNotExistException::class);
		$this->itemMapper->findByFileId(999);
	}

	public function testInsertGetDelete() {
		$item = new Item();
		$item->setFileid(1);
		$item->setCheckTime(123);

		$this->itemMapper->insert($item);

		$retrievedItem = $this->itemMapper->findByFileId(1);
		$this->assertEquals(123, $retrievedItem->getCheckTime());

		$this->itemMapper->findByFileId(1);
	}
}
