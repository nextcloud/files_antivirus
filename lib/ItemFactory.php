<?php

declare(strict_types=1);

/**
 * @copyright Copyright (c) 2018 Roeland Jago Douma <roeland@famdouma.nl>
 *
 * @author Roeland Jago Douma <roeland@famdouma.nl>
 * @author Côme Chilliet <come.chilliet@nextcloud.com>
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
use OCP\App\IAppManager;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Files\File;
use OCP\Files\IRootFolder;
use Psr\Log\LoggerInterface;

class ItemFactory {
	private AppConfig $config;
	private ActivityManager $activityManager;
	private ItemMapper $itemMapper;
	private LoggerInterface $logger;
	private IRootFolder $rootFolder;
	private IAppManager $appManager;
	private ITimeFactory $clock;

	public function __construct(
		AppConfig $appConfig,
		ActivityManager $activityManager,
		ItemMapper $itemMapper,
		LoggerInterface $logger,
		IRootFolder $rootFolder,
		IAppManager $appManager,
		ITimeFactory $clock
	) {
		$this->config = $appConfig;
		$this->activityManager = $activityManager;
		$this->itemMapper = $itemMapper;
		$this->logger = $logger;
		$this->rootFolder = $rootFolder;
		$this->appManager = $appManager;
		$this->clock = $clock;
	}

	public function newItem(File $file, bool $isCron = false): Item {
		return new Item(
			$this->config,
			$this->activityManager,
			$this->itemMapper,
			$this->logger,
			$this->rootFolder,
			$this->appManager,
			$file,
			$this->clock,
			$isCron
		);
	}
}
