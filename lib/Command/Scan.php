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
use OCA\Files_Antivirus\ItemFactory;
use OCA\Files_Antivirus\Scanner\ScannerFactory;
use OCP\Files\File;
use OCP\Files\IRootFolder;
use OCP\Files\NotFoundException;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
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
			->addArgument('file', InputArgument::REQUIRED, "Path of the file to scan");
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

		$scanner = $this->scannerFactory->getScanner();
		$item = $this->itemFactory->newItem($node);
		$result = $scanner->scan($item);

		switch ($result->getNumericStatus()) {
			case \OCA\Files_Antivirus\Status::SCANRESULT_UNCHECKED:
				$status = "couldn't be scanned";
				$exit = 2;
				break;
			case \OCA\Files_Antivirus\Status::SCANRESULT_CLEAN:
				$status = "is <info>clean</info>";
				$exit = 0;
				break;
			case \OCA\Files_Antivirus\Status::SCANRESULT_INFECTED:
				$status = "is <error>infected</error>";
				$exit = 1;
				break;
		}
		if ($result->getDetails()) {
			$details = ": " . $result->getDetails();
		} else {
			$details = "";
		}
		$output->writeln("<info>$path</info> $status$details");

		return $exit;
	}
}
