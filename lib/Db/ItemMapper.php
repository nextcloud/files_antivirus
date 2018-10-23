<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\Db;

use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Db\Entity;
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
		$sql = 'SELECT * FROM ' . $this->getTableName() .' WHERE fileid = ?';
		return $this->findEntity($sql, [$fileid]);
	}

	public function delete(Entity $entity) {
		if (!($entity instanceof Item)) {
			throw new \InvalidArgumentException();
		}

		$qb = $this->db->getQueryBuilder();

		$qb->delete('files_antivirus')
			->where(
				$qb->expr()->eq('fileid', $qb->createNamedParameter($entity->getFileid()))
			);
		$qb->execute();

		return $entity;
	}

	/**
	 * Creates a new entry in the db from an entity
	 * @param Entity $entity the entity that should be created
	 * @return Entity the saved entity with the set id
	 * @since 7.0.0
	 * @deprecated 14.0.0 Move over to QBMapper
	 */
	public function insert(Entity $entity){
		// get updated fields to save, fields have to be set using a setter to
		// be saved
		$properties = $entity->getUpdatedFields();
		$values = '';
		$columns = '';
		$params = [];

		// build the fields
		$i = 0;
		foreach($properties as $property => $updated) {
			$column = $entity->propertyToColumn($property);
			$getter = 'get' . ucfirst($property);

			$columns .= '`' . $column . '`';
			$values .= '?';

			// only append colon if there are more entries
			if($i < count($properties)-1){
				$columns .= ',';
				$values .= ',';
			}

			$params[] = $entity->$getter();
			$i++;

		}

		$sql = 'INSERT INTO `' . $this->tableName . '`(' .
			$columns . ') VALUES(' . $values . ')';

		$stmt = $this->execute($sql, $params);

		$stmt->closeCursor();

		return $entity;
	}
}
