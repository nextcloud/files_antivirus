<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\Controller;

use \OCP\AppFramework\Controller;
use \OCP\IRequest;
use \OCP\IL10N;
use OCP\AppFramework\Http\JSONResponse;

class RuleController extends Controller {
	
	private $logger;
	private $l10n;
	
	public function __construct($appName, IRequest $request, $logger, IL10N $l10n) {
		parent::__construct($appName, $request);
		$this->logger = $logger;
		$this->l10n = $l10n;
	}
	
	/**
	 * Returns all rules
	 * @return JSONResponse
	 */
	public function listAll() {
		$query = \OCP\DB::prepare('SELECT * FROM `*PREFIX*files_avir_status`');
		$result = $query->execute(array());
		$statuses = $result->fetchAll();
		return new JSONResponse(array('statuses'=>$statuses));
	}
	
	/**
	 * Removes all rules
	 * @return JSONResponse
	 */
	public function clear() {
		$query = \OCP\DB::prepare('DELETE FROM `*PREFIX*files_avir_status`');
		$query->execute(array());
		return new JSONResponse();
	}
	
	/**
	 * Resets a table to initial state
	 * @return JSONResponse
	 */
	public function reset() {
		$query = \OCP\DB::prepare('DELETE FROM `*PREFIX*files_avir_status`');
		$query->execute(array());
		\OCA\Files_Antivirus\Status::init();
		return new JSONResponse();
	}
	
	/**
	 * Adds/Updates a rule
	 * @param int $id
	 * @param int $statusType
	 * @param string $match
	 * @param string $description
	 * @param int $status
	 * @return JSONResponse
	 */
	public function save($id, $statusType, $match, $description, $status) {
		if ($statusType === \OCA\Files_Antivirus\Status::STATUS_TYPE_CODE){
			$field = 'result';
		} else {
			$field = 'match';
		}
		$data = array(
			intval($statusType),
			$match,
			$description,
			intval($status)
		);
		if ($id){
			$data[] = intval($id);
			$query = \OCP\DB::prepare('UPDATE `*PREFIX*files_avir_status` SET `status_type`=(?),'
				.' `'. $field .'`=(?), `description`=(?), `status`=(?) WHERE `id`=?');
		} else {
			$query = \OCP\DB::prepare('INSERT INTO `*PREFIX*files_avir_status` (`status_type`,'
				.' `'. $field .'`, `description`, `status`) VALUES (?, ?, ?, ?)');
		}
		
		$query->execute($data);
		$result = array();
		if (!$id){
			$result['id'] = \OCP\DB::insertid('`*PREFIX*files_avir_status`');
		}
		
		return new JSONResponse($result);
	}
	
	/**
	 * Deletes a rule
	 * @param int $id
	 * @return JSONResponse
	 */
	public function delete($id) {
		if($id){
			$query = \OCP\DB::prepare('DELETE FROM `*PREFIX*files_avir_status` WHERE `id`=?');
			$query->execute(array($id));
		}
		return new JSONResponse();
	}
}
