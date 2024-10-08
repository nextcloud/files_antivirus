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
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class Status extends Base {
	private BackgroundScanner $backgroundScanner;
	private AppConfig $appConfig;

	public function __construct(AppConfig $appConfig, BackgroundScanner $backgroundScanner) {
		parent::__construct();
		$this->backgroundScanner = $backgroundScanner;
		$this->appConfig = $appConfig;
	}

	protected function configure() {
		parent::configure();

		$this
			->setName('files_antivirus:status')
			->setDescription('Antivirus scanner status');
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		$verbose = (bool)$input->getOption('verbose');
		if ($this->appConfig->getAppValue('av_background_scan') !== 'on') {
			// Background checking disabled no need to continue
			$output->writeln('Antivirus background scan disabled');
			return 0;
		}

		$unscanned = $this->backgroundScanner->getUnscannedFiles();
		$count = $this->processFiles($unscanned, $output, $verbose, 'is unscanned');
		$output->writeln("$count unscanned files");

		$rescan = $this->backgroundScanner->getToRescanFiles();
		$count = $this->processFiles($rescan, $output, $verbose, 'is scheduled for re-scan');
		$output->writeln("$count files scheduled for re-scan");

		$outdated = $this->backgroundScanner->getOutdatedFiles();
		$count = $this->processFiles($outdated, $output, $verbose, 'has been updated');
		$output->writeln("$count have been updated since the last scan");

		return 0;
	}

	/**
	 * @param iterable<int> $fileIds
	 * @return int
	 */
	private function processFiles(iterable $fileIds, OutputInterface $output, bool $verbose, string $info): int {
		$count = 0;

		foreach ($fileIds as $fileId) {
			if ($verbose) {
				$node = $this->backgroundScanner->getNodeForFile($fileId);
				if ($node) {
					$path = $node->getPath();
					$output->writeln("  <info>$path</info> $info");
				} else {
					$output->writeln("  <error>warning: no file found for file $fileId</error>");
				}
			}
			$count++;
		}

		return $count;
	}
}
