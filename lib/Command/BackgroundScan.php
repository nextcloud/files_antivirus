<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2023 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
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
	public function __construct(
		private readonly AppConfig $appConfig,
		private readonly BackgroundScanner $backgroundScanner,
		private readonly IEventDispatcher $eventDispatcher,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();

		$this
			->setName('files_antivirus:background-scan')
			->setDescription('Run the background scan')
			->addOption('max', 'm', InputOption::VALUE_REQUIRED, 'Maximum number of files to process');
	}

	#[\Override]
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
			$output->writeln('  there might still be unscanned files remaining');
		}

		return 0;
	}
}
