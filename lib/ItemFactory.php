<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2018 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
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
