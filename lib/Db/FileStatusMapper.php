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
use OCP\AppFramework\Db\MultipleObjectsReturnedException;
use OCP\IDBConnection;
use OCP\ILogger;

class FileStatusMapper extends Mapper {

	/** @var ILogger */
	private $logger;

	/**
	 * FileStatusMapper constructor.
	 *
	 * @param IDBConnection $db
	 * @param ILogger $logger
	 */
	public function __construct(IDBConnection $db, ILogger $logger) {
		parent::__construct($db, 'files_avir_file_status', Item::class);
		$this->logger = $logger;
	}

	/**
	 * Find checked file or chunk based on the hash
	 *
	 * @param string $hash
	 * @return FileStatus
	 */
	public function findByHash($hash){
		try {
			$sql = 'SELECT * FROM ' . $this->getTableName() . ' WHERE hash = ?';
			$result = $this->findEntity($sql, [$hash]);
		} catch (DoesNotExistException $e) {
			$this->logger->debug('hash not found: ' . $hash, ['app' => 'files_antivirus']);
			return null;
		} catch (MultipleObjectsReturnedException $e) {
			$this->logger->debug('hash not unique: ' . $hash, ['app' => 'files_antivirus']);
			return null;
		}

		return $result;
	}

	/**
	 * @param string $hash
	 * @param int $status
	 * @return Entity
	 */
	public function insertStatus($hash, $status) {
		$entity = new FileStatus();
		$entity->setHash($hash);
		$entity->setStatus($status);
		return $this->insert($entity);
	}
}
