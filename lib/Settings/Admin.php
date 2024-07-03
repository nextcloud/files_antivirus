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
	/** @var AppConfig */
	private $config;

	public function __construct(AppConfig $config) {
		$this->config = $config;
	}

	public function getForm() {
		$data = $this->config->getAllValues();
		return new TemplateResponse('files_antivirus', 'settings', $data, 'blank');
	}

	public function getSection() {
		return 'security';
	}

	public function getPriority() {
		return  90;
	}
}
