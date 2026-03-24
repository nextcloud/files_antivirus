<?php

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
namespace OCA\Files_Antivirus\Migration;

use OCA\Files_Antivirus\AppInfo\Application;
use OCA\Files_Antivirus\AppInfo\ConfigLexicon;
use OCP\IAppConfig;
use OCP\Migration\IOutput;
use OCP\Migration\IRepairStep;

class ConvertAppConfig implements IRepairStep {
	public function __construct(
		private readonly IAppConfig $appConfig,
	) {
	}

	#[\Override]
	public function getName(): string {
		return 'Convert app config';
	}

	#[\Override]
	public function run(IOutput $output): void {
		$bl_type = $this->appConfig->getValueType(Application::APP_NAME, ConfigLexicon::AV_BLOCKLISTED_DIRECTORIES);
		if ($bl_type !== IAppConfig::VALUE_ARRAY) {
			$output->info('Converting blocklisted directories from string to array');

			$value = $this->appConfig->getValueString(Application::APP_NAME, ConfigLexicon::AV_BLOCKLISTED_DIRECTORIES);
			try {
				$value = json_decode($value, true);
			} catch (\JsonException $e) {
				$output->warning('Failed to decode blocklisted directories: ' . $e->getMessage());
				$value = [];
			}
			$this->appConfig->setValueArray(Application::APP_NAME, ConfigLexicon::AV_BLOCKLISTED_DIRECTORIES, $value);
		}

		$cmd_type = $this->appConfig->getValueType(Application::APP_NAME, ConfigLexicon::AV_CMD_OPTIONS);
		if ($cmd_type !== IAppConfig::VALUE_ARRAY) {
			$output->info('Converting command options from string to array');

			$value = $this->appConfig->getValueString(Application::APP_NAME, ConfigLexicon::AV_CMD_OPTIONS);
			$value = explode(',', $value);
			$this->appConfig->setValueArray(Application::APP_NAME, ConfigLexicon::AV_CMD_OPTIONS, $value);
		}

		$bs_type = $this->appConfig->getValueType(Application::APP_NAME, ConfigLexicon::AV_BACKGROUND_SCAN);
		if ($bs_type !== IAppConfig::VALUE_BOOL) {
			$output->info('Converting background scan from string to bool');

			$value = $this->appConfig->getValueString(Application::APP_NAME, ConfigLexicon::AV_BACKGROUND_SCAN);
			$value = $value === 'on';
			$this->appConfig->setValueBool(Application::APP_NAME, ConfigLexicon::AV_BACKGROUND_SCAN, $value);
		}
	}
}
