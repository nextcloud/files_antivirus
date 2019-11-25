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

namespace OCA\Files_Antivirus;

use OCA\Files_Antivirus\Db\ItemMapper;
use OCP\Activity\IManager as ActivityManager;
use OCP\Files\File;
use OCP\Files\IRootFolder;
use OCP\ILogger;

class ItemFactory {
	/** @var AppConfig */
	private $config;

	/** @var ActivityManager */
	private $activityManager;

	/** @var ItemMapper */
	private $itemMapper;

	/** @var ILogger */
	private $logger;

	/** @var IRootFolder */
	private $rootFolder;

	/**
	 * ItemFactory constructor.
	 *
	 * @param AppConfig $appConfig
	 * @param ActivityManager $activityManager
	 * @param ItemMapper $itemMapper
	 * @param ILogger $logger
	 * @param IRootFolder $rootFolder
	 */
	public function __construct(AppConfig $appConfig,
								ActivityManager $activityManager,
								ItemMapper $itemMapper,
								ILogger $logger,
								IRootFolder $rootFolder) {
		$this->config = $appConfig;
		$this->activityManager = $activityManager;
		$this->itemMapper = $itemMapper;
		$this->logger = $logger;
		$this->rootFolder = $rootFolder;
	}

	/**
	 * @param File $file
	 * @return Item
	 */
	public function newItem(File $file, $isCron = false) {
		return new Item(
			$this->config,
			$this->activityManager,
			$this->itemMapper,
			$this->logger,
			$this->rootFolder,
			$file,
			$isCron
		);
	}
}
