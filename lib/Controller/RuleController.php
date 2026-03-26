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
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\IRequest;
use Psr\Log\LoggerInterface;

class RuleController extends Controller {

	public function __construct(
		$appName,
		IRequest $request,
		private RuleMapper $ruleMapper,
		private LoggerInterface $logger,
	) {
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
		} catch (DoesNotExistException) {
			return new JSONResponse(['error' => 'Rule not found'], Http::STATUS_NOT_FOUND);
		} catch (\Exception $e) {
			$this->logger->error('Failed to delete rule', ['exception' => $e]);
			return new JSONResponse(['error' => 'Failed to delete rule'], Http::STATUS_INTERNAL_SERVER_ERROR);
		}
		return new JSONResponse($rule);
	}
}
