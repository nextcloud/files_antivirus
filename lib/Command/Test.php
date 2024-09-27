<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2023 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Command;

use OC\Core\Command\Base;
use OC\Security\Crypto;
use OCA\Files_Antivirus\Scanner\ScannerFactory;
use OCA\Files_Antivirus\Status;
use OCP\Files\File;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class Test extends Base {
	private ScannerFactory $scannerFactory;
	private Crypto $crypto;

	// This is the EICAR test file, encrypted using the password 'eicar' to prevent any AV scanner from picking up this file
	public const EICAR_ENCRYPTED = 'f413c7d6bb75cb67d474a36f27e776b7b51a68b2a26746465b659c7cd' .
		'f13d8dea5d5932bc1afe1e34aa28ce75127d6bd6918bbad07503d16257a843fb46ed3dff04b12' .
		'34d9b112aa556d396dc3afa0c4|cfaa1a828814db5ceb96fd8ab8f2c9e9|0b97b04d59a91ca64' .
		'73117bcec8672b64a8abf6e6dec8ae70dcc0c05d7639d3dc8329afae8480197fb6f5b366f2c89' .
		'629a01502a56f72c3bcb7eff3aeb1a6426|3';

	public function __construct(ScannerFactory $scannerFactory, Crypto $crypto) {
		parent::__construct();
		$this->scannerFactory = $scannerFactory;
		$this->crypto = $crypto;
	}

	protected function configure() {
		parent::configure();

		$this
			->setName('files_antivirus:test')
			->setDescription('Test the availability of the configured scanner')
			->addOption('debug', null, InputOption::VALUE_NONE, 'Enable debug output for supported backends');
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		$output->write('Scanning regular text: ');
		$scanner = $this->scannerFactory->getScanner('/foo.txt');
		if ($input->getOption('debug')) {
			$output->writeln('');
			$scanner->setDebugCallback(function ($content) use ($output) {
				$output->writeln($content);
			});
		}
		$result = $scanner->scanString('dummy scan content');
		if ($result->getNumericStatus() === Status::SCANRESULT_INFECTED) {
			$details = $result->getDetails();
			$output->writeln("<error>❌ $details</error>");
			return 1;
		} elseif ($result->getNumericStatus() === Status::SCANRESULT_UNCHECKED) {
			$output->writeln('<comment>- file not scanned or scan still pending</comment>');
		} else {
			$output->writeln('<info>✓</info>');
		}

		$output->write('Scanning EICAR test file: ');
		$scanner = $this->scannerFactory->getScanner('/test-virus-eicar.txt');
		if ($input->getOption('debug')) {
			$output->writeln('');
			$scanner->setDebugCallback(function ($content) use ($output) {
				$output->writeln($content);
			});
		}
		$eicar = $this->crypto->decrypt(self::EICAR_ENCRYPTED, 'eicar');
		$result = $scanner->scanString($eicar);
		if ($result->getNumericStatus() === Status::SCANRESULT_CLEAN) {
			$details = $result->getDetails();
			$output->writeln("<error>❌ file not detected $details</error>");
			return 1;
		} elseif ($result->getNumericStatus() === Status::SCANRESULT_UNCHECKED) {
			$output->writeln('<comment>- file not scanned or scan still pending</comment>');
		} elseif ($result->getNumericStatus() === Status::SCANRESULT_UNSCANNABLE) {
			$output->writeln('<comment>- file could not be scanned</comment>');
		} else {
			$output->writeln('<info>✓</info>');
		}

		// send a modified version of the EICAR because some scanners don't hold the scan request
		// by default for files that haven't been seen before.
		$output->write('Scanning modified EICAR test file: ');
		$scanner = $this->scannerFactory->getScanner('/test-virus-eicar-modified.txt');
		if ($input->getOption('debug')) {
			$output->writeln('');
			$scanner->setDebugCallback(function ($content) use ($output) {
				$output->writeln($content);
			});
		}
		$result = $scanner->scanString($eicar . uniqid());
		if ($result->getNumericStatus() === Status::SCANRESULT_CLEAN) {
			$details = $result->getDetails();
			$output->writeln("<error>❌ file not detected $details</error>");
			return 1;
		} elseif ($result->getNumericStatus() === Status::SCANRESULT_UNCHECKED) {
			$output->writeln('<comment>- file not scanned or scan still pending</comment>');
		} elseif ($result->getNumericStatus() === Status::SCANRESULT_UNSCANNABLE) {
			$output->writeln('<comment>- file could not be scanned</comment>');
		} else {
			$output->writeln('<info>✓</info>');
		}

		return 0;
	}
}
