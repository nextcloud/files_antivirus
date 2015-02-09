<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\Db;

use OCP\IDb;
use OCP\AppFramework\Db\Mapper;

use OCA\Files_Antivirus\Db\Item;

class ItemMapper extends Mapper {
	public function __construct(IDb $db) {
		parent::__construct($db, 'files_antivirus', '\OCA\Files_Antivirus\Db\Item');
	}
	
	
}
