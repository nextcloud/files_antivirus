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

use OCA\Files_Antivirus\AppInfo\Application;
use OCP\Activity\IEvent;
use OCP\Activity\IProvider;
use OCP\L10N\IFactory;

class Provider implements IProvider {

	const TYPE_VIRUS_DETECTED = 'virus_detected';
	const SUBJECT_VIRUS_DETECTED = 'virus_detected';
	const MESSAGE_FILE_DELETED = 'file_deleted';

	/** @var IFactory */
	private $languageFactory;

	public function __construct(IFactory $languageFactory) {
		$this->languageFactory = $languageFactory;
	}

	public function parse($language, IEvent $event, IEvent $previousEvent = null) {
		if ($event->getApp() !== Application::APP_NAME || $event->getType() !== self::TYPE_VIRUS_DETECTED) {
			throw new \InvalidArgumentException();
		}

		$l = $this->languageFactory->get('files_antivirus', $language);

		switch ($event->getSubject()) {
			case self::SUBJECT_VIRUS_DETECTED:
				$event->setParsedSubject($l->t('File %s is infected with %s', $event->getSubjectParameters()));
				break;
		}

		switch ($event->getMessage()) {
			case self::MESSAGE_FILE_DELETED:
				$event->setParsedMessage($l->t('It is going to be deleted'));
				break;
		}

		return $event;
	}

}
