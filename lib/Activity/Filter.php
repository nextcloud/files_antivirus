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
	public function __construct(
		private readonly IL10N $l,
		private readonly IURLGenerator $url,
	) {
	}

	#[\Override]
	public function getIdentifier(): string {
		return 'files_antivirus';
	}

	#[\Override]
	public function getName(): string {
		return $this->l->t('Antivirus');
	}

	#[\Override]
	public function getPriority(): int {
		return 70;
	}

	#[\Override]
	public function getIcon(): string {
		return $this->url->imagePath('files_antivirus', 'shield-dark.svg');
	}

	#[\Override]
	public function filterTypes(array $types): array {
		return $types;
	}

	#[\Override]
	public function allowedApps(): array {
		return ['files_antivirus'];
	}
}
