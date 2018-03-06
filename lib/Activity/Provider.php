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
use OCP\Files\IRootFolder;
use OCP\IURLGenerator;
use OCP\L10N\IFactory;

class Provider implements IProvider {

	const TYPE_VIRUS_DETECTED = 'virus_detected';

	const SUBJECT_VIRUS_DETECTED = 'virus_detected';
	const SUBJECT_VIRUS_DETECTED_UPLOAD = 'virus_detected_upload';
	const SUBJECT_VIRUS_DETECTED_SCAN = 'virus_detected_scan';

	const MESSAGE_FILE_DELETED = 'file_deleted';

	/** @var IFactory */
	private $languageFactory;

	/** @var IURLGenerator */
	private $urlGenerator;

	public function __construct(IFactory $languageFactory, IURLGenerator $urlGenerator) {
		$this->languageFactory = $languageFactory;
		$this->urlGenerator = $urlGenerator;
	}

	public function parse($language, IEvent $event, IEvent $previousEvent = null) {
		if ($event->getApp() !== Application::APP_NAME || $event->getType() !== self::TYPE_VIRUS_DETECTED) {
			throw new \InvalidArgumentException();
		}

		$l = $this->languageFactory->get('files_antivirus', $language);

		if ($event->getSubject() === self::SUBJECT_VIRUS_DETECTED) {
			$event->setParsedSubject($l->t('File %s is infected with %s', $event->getSubjectParameters()));
			if ($event->getMessage() === self::MESSAGE_FILE_DELETED) {
				$event->setParsedMessage($l->t('The file has been removed'));
			}

		} else if ($event->getSubject() === self::SUBJECT_VIRUS_DETECTED_UPLOAD) {
			$event->setParsedSubject($l->t('File containing %s detected', $event->getSubjectParameters()));

			if ($event->getMessage() === self::MESSAGE_FILE_DELETED) {
				$event->setParsedMessage($l->t('The file has been removed'));
			}
			$event->setIcon($this->urlGenerator->imagePath('files_antivirus', 'shield-green.svg'));
		} else if ($event->getSubject() === self::SUBJECT_VIRUS_DETECTED_SCAN) {
			$subject = $l->t('File {file} is infected with {virus}');

			$subject = str_replace(['{virus}'], $event->getSubjectParameters(), $subject);

			if ($event->getMessage() === self::MESSAGE_FILE_DELETED) {
				$event->setParsedMessage($l->t('The file has been removed'));

				$file = $this->getFileDeleted($event);
				$event->setIcon($this->urlGenerator->imagePath('files_antivirus', 'shield-green.svg'));
			} else {
				$file = $this->getFileExisting($event);
				$event->setIcon($this->urlGenerator->imagePath('files_antivirus', 'shield-red.svg'));
			}

			$event->setParsedSubject(str_replace('{file}', $file['name'], $subject))
				->setRichSubject($subject, ['file' => $file]);
		}

		return $event;
	}

	private function getFileExisting(IEvent $event) {
		$res = $this->getFileDeleted($event);
		$res['link'] = $this->urlGenerator->linkToRouteAbsolute('files.viewcontroller.showFile', ['fileid' => $event->getObjectId()]);
		return $res;
	}

	private function getFileDeleted(IEvent $event) {
		return [
			'id' => $event->getObjectId(),
			'name' => basename($event->getObjectName()),
			'path' => $event->getObjectName(),
		];
	}

}
