<?php
/**
 * SPDX-FileCopyrightText: 2018 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
namespace OCA\Files_Antivirus\Migration;

use OCP\BackgroundJob\IJobList;
use OCP\Migration\IOutput;
use OCP\Migration\IRepairStep;

class CleanupCronTask implements IRepairStep {
	/** @var IJobList */
	private $jobList;

	public function __construct(IJobList $jobList) {
		$this->jobList = $jobList;
	}

	public function getName() {
		return 'Cleanup cron task';
	}

	/**
	 * @return void
	 */
	public function run(IOutput $output) {
		$this->jobList->remove('OCA\Files_Antivirus\Cron\Task');
	}
}
