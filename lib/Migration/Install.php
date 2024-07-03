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
	/** @var RuleMapper */
	private $ruleMapper;

	/** @var IConfig */
	private $config;

	public function __construct(RuleMapper $ruleMapper, IConfig $config) {
		$this->ruleMapper = $ruleMapper;
		$this->config = $config;
	}

	public function getName() {
		return 'Populare default rules';
	}

	/**
	 * @return void
	 */
	public function run(IOutput $output) {
		$rules = $this->ruleMapper->findAll();

		if ($rules === []) {
			$this->ruleMapper->populate();
		}

		$this->config->setAppValue('files_antivirus', 'av_path', '/usr/bin/clamscan');
	}
}
