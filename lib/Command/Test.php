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
use OC\Security\Crypto;
use OCA\Files_Antivirus\Scanner\ScannerFactory;
use OCA\Files_Antivirus\Status;
use OCP\Files\File;
use Symfony\Component\Console\Input\InputInterface;
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
			->setDescription('Test the availability of the configured scanner');
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		$output->write("Scanning regular text: ");
		$scanner = $this->scannerFactory->getScanner();
		$result = $scanner->scanString("dummy scan content");
		if ($result->getNumericStatus() !== Status::SCANRESULT_CLEAN) {
			$details = $result->getDetails();
			$output->writeln("<error>❌ $details</error>");
			return 1;
		} else {
			$output->writeln("<info>✓</info>");
		}

		$output->write("Scanning EICAR test file: ");
		$scanner = $this->scannerFactory->getScanner();
		$eicar = $this->crypto->decrypt(self::EICAR_ENCRYPTED, 'eicar');
		$result = $scanner->scanString($eicar);
		if ($result->getNumericStatus() !== Status::SCANRESULT_INFECTED) {
			$details = $result->getDetails();
			$output->writeln("<error>❌ file not detected $details</error>");
			return 1;
		} else {
			$output->writeln("<info>✓</info>");
		}

		return 0;
	}
}
