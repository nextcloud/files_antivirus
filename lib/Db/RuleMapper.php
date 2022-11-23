<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\Db;

use OCA\Files_Antivirus\Status;
use OCP\AppFramework\Db\QBMapper;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;

class RuleMapper extends QBMapper {
	public function __construct(IDBConnection $db) {
		parent::__construct($db, 'files_avir_status', Rule::class);
	}

	/**
	 * Empty the table
	 *
	 * @return bool
	 */
	public function deleteAll() {
		$query = $this->db->getQueryBuilder();
		$query->delete('files_avir_status');
		$query->executeStatement();
		return true;
	}

	/**
	 * Find rule by id
	 *
	 * @param int $id
	 * @return Rule
	 */
	public function find(int $id) {
		$query = $this->db->getQueryBuilder();
		$query->select('*')
			->from('files_avir_status')
			->where($query->expr()->eq('id', $query->createNamedParameter($id, IQueryBuilder::PARAM_INT)));

		return $this->findEntity($query);
	}

	/**
	 *     * Get all rules
	 */
	public function findAll(): array {
		$query = $this->db->getQueryBuilder();
		$query->select('*')
			->from('files_avir_status');
		return $this->findEntities($query);
	}

	/**
	 * Get collection of rules by given exit code
	 *
	 * @param int $result
	 * @return array
	 */
	public function findByResult(int $result) {
		$query = $this->db->getQueryBuilder();
		$query->select('*')
			->from('files_avir_status')
			->where($query->expr()->eq('status_type', $query->createNamedParameter(Rule::RULE_TYPE_CODE, IQueryBuilder::PARAM_INT)))
			->andWhere($query->expr()->eq('result', $query->createNamedParameter($result, IQueryBuilder::PARAM_INT)));
		return $this->findEntities($query);
	}

	/**
	 * Get collection of rules of type Match
	 *
	 * @param int $status
	 * @return array
	 */
	public function findAllMatchedByStatus(int $status) {
		$query = $this->db->getQueryBuilder();
		$query->select('*')
			->from('files_avir_status')
			->where($query->expr()->eq('status_type', $query->createNamedParameter(Rule::RULE_TYPE_MATCH, IQueryBuilder::PARAM_INT)))
			->andWhere($query->expr()->eq('status', $query->createNamedParameter($status, IQueryBuilder::PARAM_INT)));
		return $this->findEntities($query);
	}

	/**
	 *     * Fill the table with rules used with clamav
	 */
	public function populate(): void {
		$descriptions = [
			[
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 0,
				'match' => '',
				'description' => '',
				'status' => Status::SCANRESULT_CLEAN,
			],

			[
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 1,
				'match' => '',
				'description' => '',
				'status' => Status::SCANRESULT_INFECTED,
			],

			[
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 40,
				'match' => '',
				'description' => 'Unknown option passed.',
				'status' => Status::SCANRESULT_UNCHECKED,
			],

			[
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 50,
				'match' => '',
				'description' => 'Database initialization error.',
				'status' => Status::SCANRESULT_UNCHECKED,
			],

			[
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 52,
				'match' => '',
				'description' => 'Not supported file type.',
				'status' => Status::SCANRESULT_UNCHECKED,
			],

			[
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 53,
				'match' => '',
				'description' => "Can't open directory.",
				'status' => Status::SCANRESULT_UNCHECKED,
			],

			[
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 54,
				'match' => '',
				'description' => "Can't open file. (ofm)",
				'status' => Status::SCANRESULT_UNCHECKED,
			],

			[
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 55,
				'match' => '',
				'description' => 'Error reading file. (ofm)',
				'status' => Status::SCANRESULT_UNCHECKED,
			],

			[
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 56,
				'match' => '',
				'description' => "Can't stat input file / directory.",
				'status' => Status::SCANRESULT_UNCHECKED,
			],

			[
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 57,
				'match' => '',
				'description' => "Can't get absolute path name of current working directory.",
				'status' => Status::SCANRESULT_UNCHECKED,
			],

			[
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 58,
				'match' => '',
				'description' => 'I/O error, please check your file system.',
				'status' => Status::SCANRESULT_UNCHECKED,
			],

			[
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 62,
				'match' => '',
				'description' => "Can't initialize logger.",
				'status' => Status::SCANRESULT_UNCHECKED,
			],

			[
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 63,
				'match' => '',
				'description' => "Can't create temporary files/directories (check permissions).",
				'status' => Status::SCANRESULT_UNCHECKED,
			],

			[
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 64,
				'match' => '',
				'description' => "Can't write to temporary directory (please specify another one).",
				'status' => Status::SCANRESULT_UNCHECKED,
			],

			[
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 70,
				'match' => '',
				'description' => "Can't allocate memory (calloc).",
				'status' => Status::SCANRESULT_UNCHECKED,
			],

			[
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 71,
				'match' => '',
				'description' => "Can't allocate memory (malloc).",
				'status' => Status::SCANRESULT_UNCHECKED,
			],

			[
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_MATCH,
				'result' => 0,
				'match' => '/.*: OK$/',
				'description' => '',
				'status' => Status::SCANRESULT_CLEAN,
			],

			[
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_MATCH,
				'result' => 0,
				'match' => '/.*: (.*) FOUND$/',
				'description' => '',
				'status' => Status::SCANRESULT_INFECTED,
			],

			[
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_MATCH,
				'result' => 0,
				'match' => '/.*: (.*) ERROR$/',
				'description' => '',
				'status' => Status::SCANRESULT_UNCHECKED,
			],
		];

		foreach ($descriptions as $description) {
			$rule = Rule::fromParams($description);
			$this->insert($rule);
		}
	}
}
