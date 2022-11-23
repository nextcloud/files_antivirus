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
use OCP\AppFramework\Db\QBMapper;
use OCP\DB\Exception;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;

class ItemMapper extends QBMapper {
	public function __construct(IDBConnection $db) {
		parent::__construct($db, 'files_antivirus', Item::class);
	}

	/**
	 * Find rule by id
	 *
	 * @param int $fileid
	 * @return Entity
	 * @throws DoesNotExistException
	 */
	public function findByFileId(int $fileid): Entity {
		$query = $this->db->getQueryBuilder();
		$query->select('*')
			->from('files_antivirus')
			->where($query->expr()->eq('fileid', $query->createNamedParameter($fileid, IQueryBuilder::PARAM_INT)));
		return $this->findEntity($query);
	}

	public function delete(Entity $entity): Entity {
		if (!($entity instanceof Item)) {
			throw new \InvalidArgumentException();
		}

		$query = $this->db->getQueryBuilder();
		$query->delete('files_antivirus')
			->where($query->expr()->eq('fileid', $query->createNamedParameter($entity->getFileid(), IQueryBuilder::PARAM_INT)));
		$query->executeStatement();

		return $entity;
	}

	/**
	 * Creates a new entry in the db from an entity
	 *
	 * @param Entity $entity the entity that should be created
	 * @return Entity the saved entity with the set id
	 * @throws Exception
	 * @since 14.0.0
	 */
	public function insert(Entity $entity): Entity {
		// get updated fields to save, fields have to be set using a setter to
		// be saved
		$properties = $entity->getUpdatedFields();

		$qb = $this->db->getQueryBuilder();
		$qb->insert($this->tableName);

		// build the fields
		foreach ($properties as $property => $updated) {
			$column = $entity->propertyToColumn($property);
			$getter = 'get' . ucfirst($property);
			$value = $entity->$getter();

			$type = $this->getParameterTypeForProperty($entity, $property);
			$qb->setValue($column, $qb->createNamedParameter($value, $type));
		}

		$qb->executeStatement();

		return $entity;
	}
}
