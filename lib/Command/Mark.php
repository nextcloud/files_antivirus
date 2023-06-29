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
use OCP\Files\File;
use OCP\Files\IRootFolder;
use OCP\Files\NotFoundException;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class Mark extends Base {
	private IRootFolder $rootFolder;
	private ItemFactory $itemFactory;

	public function __construct(
		IRootFolder $rootFolder,
		ItemFactory $itemFactory
	) {
		parent::__construct();
		$this->rootFolder = $rootFolder;
		$this->itemFactory = $itemFactory;
	}

	protected function configure() {
		parent::configure();

		$this
			->setName('files_antivirus:mark')
			->setDescription('Mark a file as scanned or unscanned')
			->addOption('forever', 'f', InputOption::VALUE_NONE, "When marking a file as scanned, set it to never rescan the file in the future")
			->addArgument('file', InputArgument::REQUIRED, "Path of the file to mark")
			->addArgument('mode', InputArgument::REQUIRED, "Either <info>scanned</info> or <info>unscanned</info>");
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		$path = $input->getArgument('file');
		$forever = $input->getOption('forever');
		$mode = $input->getArgument('mode');
		try {
			$node = $this->rootFolder->get($path);
		} catch (NotFoundException $e) {
			$output->writeln("<error>$path doesn't exist</error>");
			return 1;
		}
		if (!$node instanceof File) {
			$output->writeln("<error>$path is a folder</error>");
			return 1;
		}

		if ($mode !== 'scanned' && $mode !== 'unscanned') {
			$output->writeln("invalid mode <error>$mode</error>, please specify either <info>scanned</info> or <info>unscanned</info>");
			return 1;
		}

		$item = $this->itemFactory->newItem($node);
		if ($mode === 'unscanned') {
			$item->removeCheckTime();
		} elseif ($forever) {
			$item->updateCheckTime(0x7fffffff); // check time is still 32b
		} else {
			$item->processClean();
		}

		return 0;
	}
}
