<?php

declare(strict_types=1);
/**
 * @copyright Copyright (c) 2023 Robin Appelman <robin@icewind.nl>
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

namespace OCA\Files_Antivirus\Command;

use OC\Core\Command\Base;
use OCA\Files_Antivirus\AppConfig;
use OCA\Files_Antivirus\BackgroundJob\BackgroundScanner;
use OCA\Files_Antivirus\Event\BeforeBackgroundScanEvent;
use OCP\EventDispatcher\IEventDispatcher;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class BackgroundScan extends Base {
	private BackgroundScanner $backgroundScanner;
	private AppConfig $appConfig;
	private IEventDispatcher $eventDispatcher;

	public function __construct(AppConfig $appConfig, BackgroundScanner $backgroundScanner, IEventDispatcher $eventDispatcher) {
		parent::__construct();
		$this->backgroundScanner = $backgroundScanner;
		$this->eventDispatcher = $eventDispatcher;
		$this->appConfig = $appConfig;
	}

	protected function configure() {
		parent::configure();

		$this
			->setName('files_antivirus:background-scan')
			->setDescription('Run the background scan')
			->addOption('max', 'm', InputOption::VALUE_REQUIRED, "Maximum number of files to process");
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		$verbose = (bool)$input->getOption('verbose');
		if ($this->appConfig->getAppValue('av_background_scan') !== 'on') {
			// Background checking disabled no need to continue
			$output->writeln('Antivirus background scan disabled');
			return 0;
		}
		$max = (int)$input->getOption('max');
		if (!$max) {
			$max = PHP_INT_MAX;
		}

		if ($verbose) {
			$this->eventDispatcher->addListener(BeforeBackgroundScanEvent::class, function (BeforeBackgroundScanEvent $event) use ($output) {
				$path = $event->getFile()->getPath();
				$output->writeln("scanning <info>$path</info>");
			});
		}

		$count = $this->backgroundScanner->scan($max);

		$output->writeln("scanned <info>$count</info> files");
		if ($count === $max) {
			$output->writeln("  there might still be unscanned files remaining");
		}

		return 0;
	}
}
