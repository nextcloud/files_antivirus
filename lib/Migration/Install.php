<?php

/**
 * SPDX-FileCopyrightText: 2018 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
namespace OCA\Files_Antivirus\Migration;

use OCA\Files_Antivirus\Db\RuleMapper;
use OCP\IConfig;
use OCP\Migration\IOutput;
use OCP\Migration\IRepairStep;

class Install implements IRepairStep {
	public function __construct(
		private readonly RuleMapper $ruleMapper,
		private readonly IConfig $config,
	) {
	}

	#[\Override]
	public function getName(): string {
		return 'Populare default rules';
	}

	#[\Override]
	public function run(IOutput $output): void {
		$rules = $this->ruleMapper->findAll();

		if ($rules === []) {
			$this->ruleMapper->populate();
		}

		$this->config->setAppValue('files_antivirus', 'av_path', '/usr/bin/clamscan');
	}
}
