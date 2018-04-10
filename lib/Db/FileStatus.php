<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\Db;

use OCP\AppFramework\Db\Entity;

/**
 * Class Item
 *
 * @package OCA\Files_Antivirus\Db
 *
 * @method int getHash()
 * @method setHash(string $hash)
 * @method int getStatus()
 * @method setStatus(int $status)
 */
class FileStatus extends Entity {
	/**
	 * hash of checked file or chunk
	 * @var string
	 */
	protected $hash;

	/**
	 * check result ('1' = infected)
	 * @var int
	 */
	protected $status;
}
