<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus;

use OC\L10N\Factory;
use OCP\Activity\IExtension;
use OCP\IURLGenerator;

class Activity implements IExtension {
	
	const APP_NAME = 'files_antivirus';

	/**
	 * Filter with all app related activities
	 */
	const FILTER_AVIR = 'files_antivirus';

	/**
	 * Activity types known to this extension
	 */
	const TYPE_VIRUS_DETECTED = 'virus_detected';

	/**
	 * Subject keys for translation of the subjections
	 */
	const SUBJECT_VIRUS_DETECTED = 'virus_detected';
	
	/**
	 * Infected file deletion notice
	 */
	const MESSAGE_FILE_DELETED = 'file_deleted';


	/** @var Factory */
	protected $languageFactory;

	/** @var IURLGenerator */
	protected $URLGenerator;

	/**
	 * @param Factory $languageFactory
	 * @param IURLGenerator $URLGenerator
	 */
	public function __construct(Factory $languageFactory, IURLGenerator $URLGenerator) {
		$this->languageFactory = $languageFactory;
		$this->URLGenerator = $URLGenerator;
	}

	protected function getL10N($languageCode = null) {
		return $this->languageFactory->get(self::APP_NAME, $languageCode);
	}

	/**
	 * The extension can return an array of additional notification types.
	 * If no additional types are to be added false is to be returned
	 *
	 * @param string $languageCode
	 * @return array|false
	 */
	public function getNotificationTypes($languageCode) {
		$l = $this->getL10N($languageCode);

		return [
			self::TYPE_VIRUS_DETECTED => (string) $l->t('<strong>Infected file</strong> has been <strong>found</strong>'),
		];
	}

	/**
	 * For a given method additional types to be displayed in the settings can be returned.
	 * In case no additional types are to be added false is to be returned.
	 *
	 * @param string $method
	 * @return array|false
	 */
	public function getDefaultTypes($method) {
		$defaultTypes = [
			self::TYPE_VIRUS_DETECTED,
		];

		return $defaultTypes;
	}

	/**
	 * A string naming the css class for the icon to be used can be returned.
	 * If no icon is known for the given type false is to be returned.
	 *
	 * @param string $type
	 * @return string|false
	 */
	public function getTypeIcon($type) {
		switch ($type) {
			case self::TYPE_VIRUS_DETECTED:
				return 'icon-info';
		}
		return false;
	}

	/**
	 * The extension can translate a given message to the requested languages.
	 * If no translation is available false is to be returned.
	 *
	 * @param string $app
	 * @param string $text
	 * @param array $params
	 * @param boolean $stripPath
	 * @param boolean $highlightParams
	 * @param string $languageCode
	 * @return string|false
	 */
	public function translate($app, $text, $params, $stripPath, $highlightParams, $languageCode) {
		$l = $this->getL10N($languageCode);

		if ($app === self::APP_NAME) {
			switch ($text) {
				case self::SUBJECT_VIRUS_DETECTED:
					return (string) $l->t('File %s is infected with %s', $params);
				case self::MESSAGE_FILE_DELETED:
					return (string) $l->t('It is going to be deleted', $params);
			}
		}

		return false;
	}

	/**
	 * The extension can define the type of parameters for translation
	 *
	 * Currently known types are:
	 * * file		=> will strip away the path of the file and add a tooltip with it
	 * * username	=> will add the avatar of the user
	 *
	 * @param string $app
	 * @param string $text
	 * @return array|false
	 */
	public function getSpecialParameterList($app, $text) {
		return false;
	}

	/**
	 * The extension can define the parameter grouping by returning the index as integer.
	 * In case no grouping is required false is to be returned.
	 *
	 * @param array $activity
	 * @return integer|false
	 */
	public function getGroupParameter($activity) {
		return false;
	}

	/**
	 * The extension can define additional navigation entries. The array returned has to contain two keys 'top'
	 * and 'apps' which hold arrays with the relevant entries.
	 * If no further entries are to be added false is no be returned.
	 *
	 * @return array|false
	 */
	public function getNavigation() {
		$l = $this->getL10N();
		return [
			'apps' => [
				self::FILTER_AVIR => [
					'id' => self::FILTER_AVIR,
					'name' => (string) $l->t('Antivirus'),
					'url' => $this->URLGenerator->linkToRoute('activity.Activities.showList', ['filter' => self::FILTER_AVIR]),
				],
			],
			'top' => []
		];
	}

	/**
	 * The extension can check if a customer filter (given by a query string like filter=abc) is valid or not.
	 *
	 * @param string $filterValue
	 * @return boolean
	 */
	public function isFilterValid($filterValue) {
		return $filterValue === self::FILTER_AVIR;
	}

	/**
	 * The extension can filter the types based on the filter if required.
	 * In case no filter is to be applied false is to be returned unchanged.
	 *
	 * @param array $types
	 * @param string $filter
	 * @return array|false
	 */
	public function filterNotificationTypes($types, $filter) {
		return $filter === self::FILTER_AVIR ? [self::TYPE_VIRUS_DETECTED] : $types;
	}

	/**
	 * For a given filter the extension can specify the sql query conditions including parameters for that query.
	 * In case the extension does not know the filter false is to be returned.
	 * The query condition and the parameters are to be returned as array with two elements.
	 * E.g. return array('`app` = ? and `message` like ?', array('mail', 'ownCloud%'));
	 *
	 * @param string $filter
	 * @return array|false
	 */
	public function getQueryForFilter($filter) {
		if ($filter === self::FILTER_AVIR) {
			return [
				'(`app` = ?)',
				[self::APP_NAME],
			];
		}
		return false;
	}
}
