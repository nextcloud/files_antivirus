<?php

/**
 * SPDX-FileCopyrightText: 2018 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
namespace OCA\Files_Antivirus\Activity;

use OCP\Activity\ISetting;
use OCP\IL10N;

class Setting implements ISetting {
	public function __construct(
		private readonly IL10N $l
	) {
	}

	#[\Override]
	public function getIdentifier(): string {
		return Provider::TYPE_VIRUS_DETECTED;
	}

	#[\Override]
	public function getName(): string {
		return $this->l->t('Antivirus detected a virus');
	}

	#[\Override]
	public function getPriority(): int {
		return 70;
	}

	#[\Override]
	public function canChangeStream(): bool {
		return false;
	}

	#[\Override]
	public function isDefaultEnabledStream(): bool {
		return true;
	}

	#[\Override]
	public function canChangeMail(): bool {
		return false;
	}

	#[\Override]
	public function isDefaultEnabledMail(): bool {
		return false;
	}
}
