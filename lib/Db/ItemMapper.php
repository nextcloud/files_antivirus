<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\Db;

use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Db\Mapper;
use OCP\IDBConnection;

class ItemMapper extends Mapper {
	public function __construct(IDBConnection $db) {
		parent::__construct($db, 'files_antivirus', Item::class);
	}

	/**
	 * Find rule by id
	 * @param int $fileid
	 * @return Rule
	 * @throws DoesNotExistException
	 */
	public function findByFileId($fileid){
		$sql = 'SELECT * FROM ' . $this->getTableName() .' WHERE id = ?';
		return $this->findEntity($sql, [$fileid]);
	}
}
