<?php
/**
 * SPDX-FileCopyrightText: 2018 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
namespace OCA\Files_Antivirus\Activity;

use OCP\Activity\IFilter;
use OCP\IL10N;
use OCP\IURLGenerator;

class Filter implements IFilter {
	/** @var IL10N */
	private $l;

	/** @var IURLGenerator */
	private $url;

	public function __construct(IL10N $l, IURLGenerator $url) {
		$this->l = $l;
		$this->url = $url;
	}

	public function getIdentifier() {
		return 'files_antivirus';
	}

	public function getName() {
		return $this->l->t('Antivirus');
	}

	public function getPriority() {
		return 70;
	}

	public function getIcon() {
		return $this->url->imagePath('files_antivirus', 'shield-dark.svg');
	}

	public function filterTypes(array $types) {
		return $types;
	}

	public function allowedApps() {
		return ['files_antivirus'];
	}
}
