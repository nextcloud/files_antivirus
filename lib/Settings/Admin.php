<?php
/**
 * @copyright Copyright (c) 2018 Roeland Jago Douma <roeland@famdouma.nl>
 *
 * @author Roeland Jago Douma <roeland@famdouma.nl>
 * @author Carl Schwan <carl@carlschwan.eu>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
namespace OCA\Files_Antivirus\Settings;

use OCA\Files_Antivirus\AppConfig;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\IL10N;
use OCP\Settings\IDelegatedSettings;

class Admin implements IDelegatedSettings {

	/** @var AppConfig */
	private $config;

	/** @var IL10n */
	private $l;

	public function __construct(AppConfig $config, IL10n $l) {
		$this->config = $config;
		$this->l = $l;
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

	public function getName(): string {
		return $this->l->t("Antivirus");
	}

	public function getAuthorizedAppConfig(): array {
		return [
			'files_antivirus' => ['.*'],
		];
	}
}
