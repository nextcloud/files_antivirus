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
use OCP\IURLGenerator;
use OCP\Settings\ISettings;
use OCP\Util;

class Admin implements ISettings {
	public function __construct(
		private readonly ConfigLexicon $configLexicon,
		private readonly IInitialState $initialState,
		private readonly IURLGenerator $urlGenerator,
	) {
	}

	#[\Override]
	public function getForm() {
		$data = $this->configLexicon->getAllConfigValues();

		$this->initialState->provideInitialState('config', $data);
		$this->initialState->provideInitialState('docUrl', $this->urlGenerator->linkToDocs('admin-antivirus-configuration'));

		Util::addStyle(Application::APP_NAME, Application::APP_NAME . '-adminSettings');
		Util::addScript(Application::APP_NAME, Application::APP_NAME . '-adminSettings');
		return new TemplateResponse(Application::APP_NAME, 'settings', renderAs: TemplateResponse::RENDER_AS_BLANK);
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
