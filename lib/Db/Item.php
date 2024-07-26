<?php

/**
 * SPDX-FileCopyrightText: 2017-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2015-2016 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
namespace OCA\Files_Antivirus\Db;

use OCP\AppFramework\Db\Entity;

/**
 * Class Item
 *
 * @package OCA\Files_Antivirus\Db
 *
 * @method int getFileid()
 * @method setFileid(int $id)
 * @method int getCheckTime()
 * @method setCheckTime(int $time)
 */
class Item extends Entity {
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
