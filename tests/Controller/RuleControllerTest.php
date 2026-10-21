<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests\Controller;

use OCA\Files_Antivirus\AuditLog\Operation;
use OCA\Files_Antivirus\Controller\RuleController;
use OCA\Files_Antivirus\Db\Rule;
use OCA\Files_Antivirus\Db\RuleMapper;
use OCA\Files_Antivirus\Status;
use OCA\Files_Antivirus\Tests\AuditLog\AuditEvents;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Http;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IRequest;
use OCP\Log\Audit\CriticalActionPerformedEvent;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class RuleControllerTest extends TestCase {
	private RuleMapper&MockObject $ruleMapper;
	private IEventDispatcher&MockObject $eventDispatcher;
	private RuleController $controller;

	protected function setUp(): void {
		parent::setUp();

		$this->ruleMapper = $this->createMock(RuleMapper::class);
		$this->eventDispatcher = $this->createMock(IEventDispatcher::class);

		$this->controller = new RuleController(
			'files_antivirus',
			$this->createMock(IRequest::class),
			$this->ruleMapper,
			$this->createMock(LoggerInterface::class),
			$this->eventDispatcher,
		);
	}

	private function expectAuditEvent(Operation $operation, string $message, array $parameters): void {
		$this->eventDispatcher->expects($this->once())
			->method('dispatchTyped')
			->willReturnCallback(function (CriticalActionPerformedEvent $event) use ($operation, $message, $parameters): void {
				$this->assertTrue(AuditEvents::hasOperation($event, $operation->value));
				$this->assertSame($message, $event->getLogMessage());
				$this->assertSame($parameters, $event->getParameters());
			});
	}

	private function createRule(int $id): Rule {
		$rule = new Rule();
		$rule->setId($id);
		$rule->setStatusType(Rule::RULE_TYPE_MATCH);
		$rule->setStatus(Status::SCANRESULT_CLEAN);
		return $rule;
	}

	public function testClear(): void {
		$this->ruleMapper->expects($this->once())->method('deleteAll');
		$this->expectAuditEvent(Operation::RulesCleared, 'All antivirus rules were deleted', []);

		$this->controller->clear();
	}

	public function testReset(): void {
		$this->ruleMapper->expects($this->once())->method('deleteAll');
		$this->ruleMapper->expects($this->once())->method('populate');
		$this->expectAuditEvent(Operation::RulesReset, 'Antivirus rules were reset to the defaults', []);

		$this->controller->reset();
	}

	public function testResetFailureIsNotLogged(): void {
		$this->ruleMapper->method('populate')->willThrowException(new \Exception('Database error'));
		$this->eventDispatcher->expects($this->never())->method('dispatchTyped');

		$this->expectException(\Exception::class);
		$this->controller->reset();
	}

	public function testSaveCreatesRule(): void {
		$this->ruleMapper->expects($this->never())->method('find');
		$this->ruleMapper->expects($this->once())
			->method('insert')
			->willReturnCallback(function (Rule $rule): Rule {
				$rule->setId(7);
				return $rule;
			});
		$this->expectAuditEvent(Operation::RuleCreated, 'Antivirus rule %s was created', [
			'ruleId' => 7,
			'statusType' => Rule::RULE_TYPE_MATCH,
			'status' => Status::SCANRESULT_CLEAN,
		]);

		$this->controller->save(null, Rule::RULE_TYPE_MATCH, 'Heuristics.Encrypted', 'Encrypted files', Status::SCANRESULT_CLEAN);
	}

	public function testSaveUpdatesRule(): void {
		$rule = $this->createRule(3);
		$this->ruleMapper->method('find')->with(3)->willReturn($rule);
		$this->ruleMapper->expects($this->once())->method('update')->with($rule)->willReturn($rule);
		$this->expectAuditEvent(Operation::RuleUpdated, 'Antivirus rule %s was updated', [
			'ruleId' => 3,
			'statusType' => Rule::RULE_TYPE_CODE,
			'status' => Status::SCANRESULT_INFECTED,
		]);

		$this->controller->save(3, Rule::RULE_TYPE_CODE, '1', 'Infected', Status::SCANRESULT_INFECTED);
	}

	public function testSaveUnknownRuleIsNotLogged(): void {
		$this->ruleMapper->method('find')->willThrowException(new DoesNotExistException(''));
		$this->eventDispatcher->expects($this->never())->method('dispatchTyped');

		$this->expectException(DoesNotExistException::class);
		$this->controller->save(3, Rule::RULE_TYPE_CODE, '1', 'Infected', Status::SCANRESULT_INFECTED);
	}

	public function testDelete(): void {
		$rule = $this->createRule(5);
		$this->ruleMapper->method('find')->with(5)->willReturn($rule);
		$this->ruleMapper->expects($this->once())->method('delete')->with($rule);
		$this->expectAuditEvent(Operation::RuleDeleted, 'Antivirus rule %s was deleted', [
			'ruleId' => 5,
			'statusType' => Rule::RULE_TYPE_MATCH,
			'status' => Status::SCANRESULT_CLEAN,
		]);

		$this->controller->delete(5);
	}

	public function testDeleteUnknownRuleIsNotLogged(): void {
		$this->ruleMapper->method('find')->willThrowException(new DoesNotExistException(''));
		$this->eventDispatcher->expects($this->never())->method('dispatchTyped');

		$response = $this->controller->delete(5);

		$this->assertSame(Http::STATUS_NOT_FOUND, $response->getStatus());
	}

	public function testDeleteFailureIsNotLogged(): void {
		$rule = $this->createRule(5);
		$this->ruleMapper->method('find')->willReturn($rule);
		$this->ruleMapper->method('delete')->willThrowException(new \Exception('Database error'));
		$this->eventDispatcher->expects($this->never())->method('dispatchTyped');

		$response = $this->controller->delete(5);

		$this->assertSame(Http::STATUS_INTERNAL_SERVER_ERROR, $response->getStatus());
	}
}
