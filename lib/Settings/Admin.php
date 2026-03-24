<?php

/**
 * SPDX-FileCopyrightText: 2018 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
namespace OCA\Files_Antivirus\Settings;

use OCA\Files_Antivirus\AppInfo\Application;
use OCA\Files_Antivirus\AppInfo\ConfigLexicon;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\AppFramework\Services\IInitialState;
use OCP\Settings\ISettings;

class Admin implements ISettings {
	public function __construct(
		private readonly ConfigLexicon $configLexicon,
		private readonly IInitialState $initialState,
	) {
	}

	#[\Override]
	public function getForm() {
		$data = $this->configLexicon->getAllConfigValues();

		return new TemplateResponse('files_antivirus', 'settings', $data, TemplateResponse::RENDER_AS_BLANK);
	}

	#[\Override]
	public function getSection() {
		return 'security';
	}

	#[\Override]
	public function getPriority() {
		return 90;
	}
}
