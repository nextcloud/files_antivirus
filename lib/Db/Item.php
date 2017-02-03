<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\Db;

use OCP\AppFramework\Db\Entity;

class Item extends Entity{
	/**
	 * fileid that was scanned
	 * @var int
	 */
	protected $fileid;
	
	/**
	 * Timestamp of the check
	 * @var int
	 */
	protected $checkTime;
	
}
