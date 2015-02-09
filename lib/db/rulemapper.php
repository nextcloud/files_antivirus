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

use OCA\Files_Antivirus\Db\Rule;

class RuleMapper extends Mapper {
	public function __construct(IDb $db) {
		parent::__construct($db, 'files_avir_status', '\OCA\Files_Antivirus\Db\Rule');
	}
	
	/**
	 * Empty the table
	 * @return bool
	 */
	public function deleteAll(){
		$sql = 'DELETE FROM `*PREFIX*files_avir_status`';
		return $this->execute($sql);
	}
	
	/**
	 * Find rule by id
	 * @param int $id
	 * @return Rule
	 */
	public function find($id){
        $sql = 'SELECT * FROM *PREFIX*files_avir_status WHERE id = ?';
        return $this->findEntity($sql, array($id));
	}
	
	/**
	 * Get all rules
	 */
	public function findAll(){
		$sql = 'SELECT * FROM `*PREFIX*files_avir_status`';
        return $this->findEntities($sql);
	}

	/**
	 * Get collection of rules by given exit code
	 * @param int $result
	 * @return array
	 */
	public function findByResult($result){
		$sql = 'SELECT * FROM `*PREFIX*files_avir_status` WHERE `status_type`=? and `result`=?';
		return $this->findEntities($sql, array(Rule::RULE_TYPE_CODE, $result));
	}
	
	/**
	 * Get collection of rules of type Match
	 * @param int $status
	 * @return array
	 */
	public function findAllMatchedByStatus($status){
		$sql = 'SELECT * FROM `*PREFIX*files_avir_status` WHERE `status_type`=? and `status`=?';
		return $this->findEntities($sql, array(Rule::RULE_TYPE_MATCH, $status));
	}
	
	/**
	 * Fill the table with rules used with clamav
	 */
	public function populate(){
		$descriptions = array(
			array(
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 0,
				'match' => '',
				'description' => "",
				'status' => \OCA\Files_Antivirus\Status::SCANRESULT_CLEAN
			),

			array(
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 1,
				'match' => '',
				'description' => "",
				'status' => \OCA\Files_Antivirus\Status::SCANRESULT_INFECTED
			),
		
			array(
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 40,
				'match' => '',
				'description' => "Unknown option passed.",
				'status' => \OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED
			),
			
			array(
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 50,
				'match' => '',
				'description' => "Database initialization error.",
				'status' => \OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED
			),
			
			array(
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 52,
				'match' => '',
				'description' => "Not supported file type.",
				'status' => \OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED
			),
			
			array(
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 53,
				'match' => '',
				'description' => "Can't open directory.",
				'status' => \OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED
			),
			
			array(
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 54,
				'match' => '',
				'description' => "Can't open file. (ofm)",
				'status' => \OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED
			),
			
			array(
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 55,
				'match' => '',
				'description' => "Error reading file. (ofm)",
				'status' => \OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED
			),
			
			array(
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 56,
				'match' => '',
				'description' => "Can't stat input file / directory.",
				'status' => \OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED
			),
			
			array(
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 57,
				'match' => '',
				'description' => "Can't get absolute path name of current working directory.",
				'status' => \OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED
			),
			
			array(
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 58,
				'match' => '',
				'description' => "I/O error, please check your file system.",
				'status' => \OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED
			),
			
			array(
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 62,
				'match' => '',
				'description' => "Can't initialize logger.",
				'status' => \OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED
			),
			
			array(
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 63,
				'match' => '',
				'description' => "Can't create temporary files/directories (check permissions).",
				'status' => \OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED
			),
			
			array(
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 64,
				'match' => '',
				'description' => "Can't write to temporary directory (please specify another one).",
				'status' => \OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED
			),
			
			array(
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 70,
				'match' => '',
				'description' => "Can't allocate memory (calloc).",
				'status' => \OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED
			),
			
			array(
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_CODE,
				'result' => 71,
				'match' => '',
				'description' => "Can't allocate memory (malloc).",
				'status' => \OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED
			),
			
			array(
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_MATCH,
				'result' => 0,
				'match' => '/.*: OK$/',
				'description' => '',
				'status' => \OCA\Files_Antivirus\Status::SCANRESULT_CLEAN
			),
			
			array(
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_MATCH,
				'result' => 0,
				'match' => '/.*: (.*) FOUND$/',
				'description' => '',
				'status' => \OCA\Files_Antivirus\Status::SCANRESULT_INFECTED
			),
			
			array(
				'groupId' => 0,
				'statusType' => Rule::RULE_TYPE_MATCH,
				'result' => 0,
				'match' => '/.*: (.*) ERROR$/',
				'description' => '',
				'status' => \OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED
			),
		);
		
		foreach ($descriptions as $description){
			$rule = Rule::fromParams($description);
			$this->insert($rule);
		}
	}
}
