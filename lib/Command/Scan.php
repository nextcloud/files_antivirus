<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2023 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Command;

use OC\Core\Command\Base;
use OCA\Files_Antivirus\ItemFactory;
use OCA\Files_Antivirus\Scanner\ScannerFactory;
use OCP\Files\File;
use OCP\Files\IRootFolder;
use OCP\Files\NotFoundException;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class Scan extends Base {
	private ScannerFactory $scannerFactory;
	private IRootFolder $rootFolder;
	private ItemFactory $itemFactory;

	public function __construct(
		IRootFolder $rootFolder,
		ScannerFactory $scannerFactory,
		ItemFactory $itemFactory
	) {
		parent::__construct();
		$this->rootFolder = $rootFolder;
		$this->scannerFactory = $scannerFactory;
		$this->itemFactory = $itemFactory;
	}

	protected function configure() {
		parent::configure();

		$this
			->setName('files_antivirus:scan')
			->setDescription('Scan a file')
			->addArgument('file', InputArgument::REQUIRED, 'Path of the file to scan')
			->addOption('debug', null, InputOption::VALUE_NONE, 'Enable debug output for supported backends');
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		$path = $input->getArgument('file');
		try {
			$node = $this->rootFolder->get($path);
		} catch (NotFoundException $e) {
			$output->writeln("<error>$path doesn't exist</error>");
			return 3;
		}
		if (!$node instanceof File) {
			$output->writeln("<error>$path is a folder</error>");
			return 3;
		}

		$scanner = $this->scannerFactory->getScanner($node->getPath());
		if ($input->getOption('debug')) {
			$scanner->setDebugCallback(function ($content) use ($output) {
				$output->writeln($content);
			});
		}
		$item = $this->itemFactory->newItem($node);
		$result = $scanner->scan($item);

		switch ($result->getNumericStatus()) {
			case \OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED:
				$status = "couldn't be scanned";
				$exit = 2;
				break;
			case \OCA\Files_Antivirus\Status::SCANRESULT_CLEAN:
				$status = 'is <info>clean</info>';
				$exit = 0;
				break;
			case \OCA\Files_Antivirus\Status::SCANRESULT_INFECTED:
				$status = 'is <error>infected</error>';
				$exit = 1;
				break;
			case \OCA\Files_Antivirus\Status::SCANRESULT_UNSCANNABLE:
				$status = 'is not scannable';
				$exit = 2;
				break;
		}
		if ($result->getDetails()) {
			$details = ': ' . $result->getDetails();
		} else {
			$details = '';
		}
		$output->writeln("<info>$path</info> $status$details");

		return $exit;
	}
}
