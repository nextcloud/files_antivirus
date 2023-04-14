<?php
/**
 * @copyright Copyright (c) 2018 Roeland Jago Douma <roeland@famdouma.nl>
 *
 * @author Roeland Jago Douma <roeland@famdouma.nl>
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
