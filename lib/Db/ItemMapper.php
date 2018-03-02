<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\Db;

use OCP\AppFramework\Db\Mapper;
use OCP\IDBConnection;

class ItemMapper extends Mapper {
	public function __construct(IDBConnection $db) {
		parent::__construct($db, 'files_antivirus', Item::class);
	}
}
