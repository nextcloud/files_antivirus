<?php

/**
 * SPDX-FileCopyrightText: 2018 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
namespace OCA\Files_Antivirus\Settings;

use OCA\Files_Antivirus\AppConfig;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\Settings\ISettings;

class Admin implements ISettings {
	public function __construct(
		private readonly AppConfig $config
	) {
	}

	#[\Override]
	public function getForm() {
		$data = $this->config->getAllValues();
		return new TemplateResponse('files_antivirus', 'settings', $data, TemplateResponse::RENDER_AS_BLANK);
	}

	#[\Override]
	public function getSection() {
		return 'security';
	}

	#[\Override]
	public function getPriority() {
		return  90;
	}
}
