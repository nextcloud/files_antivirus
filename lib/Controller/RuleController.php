<?php

/**
 * SPDX-FileCopyrightText: 2018-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2015 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Controller;

use OCA\Files_Antivirus\AuditLog\AuditEventFactory;
use OCA\Files_Antivirus\AuditLog\Operation;
use OCA\Files_Antivirus\Db\Rule;
use OCA\Files_Antivirus\Db\RuleMapper;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IRequest;
use Psr\Log\LoggerInterface;

class RuleController extends Controller {

	public function __construct(
		$appName,
		IRequest $request,
		private RuleMapper $ruleMapper,
		private LoggerInterface $logger,
		private IEventDispatcher $eventDispatcher,
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
		$this->logAuditEvent(Operation::RulesCleared, 'All antivirus rules were deleted');
		return new JSONResponse();
	}

	/**
	 * Resets a table to initial state
	 * @return JSONResponse
	 */
	public function reset() {
		$this->ruleMapper->deleteAll();
		$this->ruleMapper->populate();
		$this->logAuditEvent(Operation::RulesReset, 'Antivirus rules were reset to the defaults');
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

		$this->logAuditEvent(
			$id ? Operation::RuleUpdated : Operation::RuleCreated,
			$id ? 'Antivirus rule %s was updated' : 'Antivirus rule %s was created',
			$this->getRuleParameters($newRule),
		);

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
		$this->logAuditEvent(Operation::RuleDeleted, 'Antivirus rule %s was deleted', $this->getRuleParameters($rule));
		return new JSONResponse($rule);
	}

	private function getRuleParameters(Rule $rule): array {
		return [
			'ruleId' => $rule->getId(),
			'statusType' => $rule->getStatusType(),
			'status' => $rule->getStatus(),
		];
	}

	private function logAuditEvent(Operation $operation, string $message, array $parameters = []): void {
		$this->eventDispatcher->dispatchTyped(AuditEventFactory::create($operation, $message, $parameters));
	}
}
