<?php

/**
 * SPDX-FileCopyrightText: 2018 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
namespace OCA\Files_Antivirus;

use OCA\Files_Antivirus\Db\RuleMapper;
use Psr\Log\LoggerInterface;

class StatusFactory {
	private RuleMapper $ruleMapper;
	private LoggerInterface $logger;

	public function __construct(RuleMapper $ruleMapper, LoggerInterface $logger) {
		$this->ruleMapper = $ruleMapper;
		$this->logger = $logger;
	}

	public function newStatus(): Status {
		return new Status(
			$this->ruleMapper,
			$this->logger
		);
	}
}
