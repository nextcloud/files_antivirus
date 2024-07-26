<?php
/**
 * SPDX-FileCopyrightText: 2018 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
namespace OCA\Files_Antivirus\Activity;

use OCA\Files_Antivirus\AppInfo\Application;
use OCP\Activity\IEvent;
use OCP\Activity\IProvider;
use OCP\IURLGenerator;
use OCP\L10N\IFactory;

class Provider implements IProvider {
	public const TYPE_VIRUS_DETECTED = 'virus_detected';

	public const SUBJECT_VIRUS_DETECTED = 'virus_detected';
	public const SUBJECT_VIRUS_DETECTED_UPLOAD = 'virus_detected_upload';
	public const SUBJECT_VIRUS_DETECTED_SCAN = 'virus_detected_scan';

	public const MESSAGE_FILE_DELETED = 'file_deleted';

	/** @var IFactory */
	private $languageFactory;

	/** @var IURLGenerator */
	private $urlGenerator;

	public function __construct(IFactory $languageFactory, IURLGenerator $urlGenerator) {
		$this->languageFactory = $languageFactory;
		$this->urlGenerator = $urlGenerator;
	}

	public function parse($language, IEvent $event, ?IEvent $previousEvent = null) {
		if ($event->getApp() !== Application::APP_NAME || $event->getType() !== self::TYPE_VIRUS_DETECTED) {
			throw new \InvalidArgumentException();
		}

		$l = $this->languageFactory->get('files_antivirus', $language);

		$parameters = [];
		$subject = '';

		if ($event->getSubject() === self::SUBJECT_VIRUS_DETECTED) {
			$subject = $l->t('File {file} is infected with {virus}');

			$params = $event->getSubjectParameters();
			$parameters['virus'] = [
				'type' => 'highlight',
				'id' => $params[1],
				'name' => $params[1],
			];

			$parameters['file'] = [
				'type' => 'highlight',
				'id' => $event->getObjectName(),
				'name' => basename($event->getObjectName()),
			];

			if ($event->getMessage() === self::MESSAGE_FILE_DELETED) {
				$event->setParsedMessage($l->t('The file has been removed'));
			}
		} elseif ($event->getSubject() === self::SUBJECT_VIRUS_DETECTED_UPLOAD) {
			$subject = $l->t('File containing {virus} detected');

			$params = $event->getSubjectParameters();
			$parameters['virus'] = [
				'type' => 'highlight',
				'id' => $params[0],
				'name' => $params[0],
			];

			if ($event->getMessage() === self::MESSAGE_FILE_DELETED) {
				$event->setParsedMessage($l->t('The file has been removed'));
			}
			$event->setIcon($this->urlGenerator->imagePath('files_antivirus', 'shield-dark.svg'));
		} elseif ($event->getSubject() === self::SUBJECT_VIRUS_DETECTED_SCAN) {
			$subject = $l->t('File {file} is infected with {virus}');

			$params = $event->getSubjectParameters();
			$parameters['virus'] = [
				'type' => 'highlight',
				'id' => $params[0],
				'name' => $params[0],
			];
			$parameters['file'] = [
				'type' => 'highlight',
				'id' => $event->getObjectName(),
				'name' => $event->getObjectName(),
			];

			if ($event->getMessage() === self::MESSAGE_FILE_DELETED) {
				$event->setParsedMessage($l->t('The file has been removed'));
				$event->setIcon($this->urlGenerator->imagePath('files_antivirus', 'shield-dark.svg'));
			} else {
				$event->setIcon($this->urlGenerator->imagePath('files_antivirus', 'shield-red.svg'));
			}
		}

		$this->setSubjects($event, $subject, $parameters);

		return $event;
	}

	private function setSubjects(IEvent $event, string $subject, array $parameters): void {
		$placeholders = $replacements = [];
		foreach ($parameters as $placeholder => $parameter) {
			$placeholders[] = '{' . $placeholder . '}';
			if ($parameter['type'] === 'file') {
				$replacements[] = $parameter['path'];
			} else {
				$replacements[] = $parameter['name'];
			}
		}

		$event->setParsedSubject(str_replace($placeholders, $replacements, $subject))
			->setRichSubject($subject, $parameters);
	}
}
