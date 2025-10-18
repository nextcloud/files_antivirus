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
	private AppConfig $config;

	public function __construct(
		RuleMapper $ruleMapper,
		LoggerInterface $logger,
		AppConfig $config
	) {
		$this->ruleMapper = $ruleMapper;
		$this->logger = $logger;
		$this->config = $config;
	}

	public function newStatus(): Status {
		return new Status(
			$this->ruleMapper,
			$this->logger,
			$this->config,
		);
	}
}
