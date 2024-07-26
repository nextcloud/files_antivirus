<?php
/**
 * SPDX-FileCopyrightText: 2018 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
namespace OCA\Files_Antivirus\Activity;

use OCP\Activity\ISetting;
use OCP\IL10N;

class Setting implements ISetting {
	/** @var IL10N */
	private $l;

	public function __construct(IL10N $l) {
		$this->l = $l;
	}

	public function getIdentifier() {
		return Provider::TYPE_VIRUS_DETECTED;
	}

	public function getName() {
		return $this->l->t('Antivirus detected a virus');
	}

	public function getPriority() {
		return 70;
	}

	public function canChangeStream() {
		return false;
	}

	public function isDefaultEnabledStream() {
		return true;
	}

	public function canChangeMail() {
		return false;
	}

	public function isDefaultEnabledMail() {
		return false;
	}
}
