<?php

/**
 * SPDX-FileCopyrightText: 2018-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2015 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
namespace OCA\Files_Antivirus\Controller;

use OCA\Files_Antivirus\Db\Rule;
use OCA\Files_Antivirus\Db\RuleMapper;
use OCP\AppFramework\Controller;

use OCP\AppFramework\Http\JSONResponse;
use OCP\IRequest;

class RuleController extends Controller {
	/** @var RuleMapper */
	private $ruleMapper;

	public function __construct($appName, IRequest $request, RuleMapper $ruleMapper) {
		parent::__construct($appName, $request);
		$this->ruleMapper = $ruleMapper;
	}

	/**
	 * Returns all rules
	 * @return JSONResponse
	 */
	public function listAll() {
		$statuses = $this->ruleMapper->findAll();
		return new JSONResponse(['statuses' => $statuses]);
	}

	/**
	 * Removes all rules
	 * @return JSONResponse
	 */
	public function clear() {
		$this->ruleMapper->deleteAll();
		return new JSONResponse();
	}

	/**
	 * Resets a table to initial state
	 * @return JSONResponse
	 */
	public function reset() {
		$this->ruleMapper->deleteAll();
		$this->ruleMapper->populate();
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
		if ($id) {
			$rule = $this->ruleMapper->find($id);
		} else {
			$rule = new Rule();
		}

		$rule->setStatusType($statusType);
		$rule->setDescription($description);
		$rule->setStatus($status);

		if ($statusType === Rule::RULE_TYPE_CODE) {
			$rule->setResult((int)$match);
		} else {
			$rule->setMatch($match);
		}

		if ($id) {
			$newRule = $this->ruleMapper->update($rule);
		} else {
			$newRule = $this->ruleMapper->insert($rule);
		}

		/** @var Rule $newRule */
		return new JSONResponse($newRule);
	}

	/**
	 * Deletes a rule
	 * @param int $id
	 * @return JSONResponse
	 */
	public function delete($id) {
		try {
			$rule = $this->ruleMapper->find($id);
			$this->ruleMapper->delete($rule);
		} catch (\Exception $e) {
			//TODO: Handle
		}
		return new JSONResponse($rule);
	}
}
