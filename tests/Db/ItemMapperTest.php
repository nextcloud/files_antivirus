<?php

declare(strict_types=1);
/**
 * @copyright Copyright (c) 2022 Robin Appelman <robin@icewind.nl>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
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
