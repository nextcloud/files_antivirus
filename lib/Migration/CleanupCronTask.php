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
	public function __construct(
		private readonly IJobList $jobList,
	) {
	}

	#[\Override]
	public function getName(): string {
		return 'Cleanup cron task';
	}

	#[\Override]
	public function run(IOutput $output): void {
		$this->jobList->remove('OCA\Files_Antivirus\Cron\Task');
	}
}
