<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests\Scanner;

use OCA\Files_Antivirus\AppInfo\ConfigLexicon;
use OCA\Files_Antivirus\Db\RuleMapper;
use OCA\Files_Antivirus\Scanner\ScannerBase;
use OCA\Files_Antivirus\Status;
use OCA\Files_Antivirus\StatusFactory;
use OCP\AppFramework\Services\IAppConfig;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class ScannerBaseTest extends TestCase {
	/** Each chunk of a file in the tests starts a new part */
	private const STREAM_MAX_LENGTH = 10;
	private const CHUNKS = ['aaaaaaaa', 'bbbbbbbb', 'cccccccc'];

	/**
	 * @param list<int> $results scan result of each part
	 * @param ?int $failingPart index of the part for which writing to the scanner fails
	 */
	private function getScanner(array $results, ?int $failingPart = null): ScannerBase {
		$config = $this->createMock(IAppConfig::class);
		$config->method('getAppValueInt')
			->willReturnCallback(fn (string $key): int => match ($key) {
				ConfigLexicon::AV_STREAM_MAX_LENGTH => self::STREAM_MAX_LENGTH,
				ConfigLexicon::AV_SCAN_FIRST_BYTES => -1,
			});
		$logger = $this->createMock(LoggerInterface::class);
		$statusFactory = new StatusFactory($this->createMock(RuleMapper::class), $logger, $config);

		return new class($config, $logger, $statusFactory, $results, $failingPart) extends ScannerBase {
			/** @var list<string> data received by the scanner for each part */
			public array $parts = [];

			/**
			 * @param list<int> $results
			 */
			public function __construct(
				IAppConfig $config,
				LoggerInterface $logger,
				StatusFactory $statusFactory,
				private array $results,
				private ?int $failingPart,
			) {
				parent::__construct($config, $logger, $statusFactory);
			}

			#[\Override]
			public function initScanner(): void {
				parent::initScanner();
				// writing to a read-only stream fails like writing to a connection closed by the daemon
				$this->writeHandle = fopen('php://memory', count($this->parts) === $this->failingPart ? 'r' : 'w+');
			}

			#[\Override]
			protected function shutdownScanner(): void {
				rewind($this->writeHandle);
				$this->parts[] = stream_get_contents($this->writeHandle);
				fclose($this->writeHandle);
				$this->status->setNumericStatus(array_shift($this->results) ?? Status::SCANRESULT_CLEAN);
			}
		};
	}

	private function scanChunks(ScannerBase $scanner): Status {
		$scanner->initScanner();
		foreach (self::CHUNKS as $chunk) {
			$scanner->onAsyncData($chunk);
		}
		return $scanner->completeAsyncScan();
	}

	public function testPartsStartWithTheLastChunkOfThePreviousPart(): void {
		$scanner = $this->getScanner([]);
		$this->scanChunks($scanner);
		$this->assertEquals(['aaaaaaaa', 'aaaaaaaabbbbbbbb', 'bbbbbbbbcccccccc'], $scanner->parts);
	}

	public static function providePartResults(): array {
		return [
			'all clean' => [[Status::SCANRESULT_CLEAN, Status::SCANRESULT_CLEAN, Status::SCANRESULT_CLEAN], Status::SCANRESULT_CLEAN],
			'unchecked first part' => [[Status::SCANRESULT_UNCHECKED, Status::SCANRESULT_CLEAN, Status::SCANRESULT_CLEAN], Status::SCANRESULT_UNCHECKED],
			'unscannable part' => [[Status::SCANRESULT_CLEAN, Status::SCANRESULT_UNSCANNABLE, Status::SCANRESULT_CLEAN], Status::SCANRESULT_UNSCANNABLE],
			'unchecked over unscannable' => [[Status::SCANRESULT_UNSCANNABLE, Status::SCANRESULT_UNCHECKED, Status::SCANRESULT_CLEAN], Status::SCANRESULT_UNCHECKED],
			'infected over unchecked' => [[Status::SCANRESULT_UNCHECKED, Status::SCANRESULT_INFECTED, Status::SCANRESULT_CLEAN], Status::SCANRESULT_INFECTED],
			'infected first part' => [[Status::SCANRESULT_INFECTED, Status::SCANRESULT_UNCHECKED, Status::SCANRESULT_CLEAN], Status::SCANRESULT_INFECTED],
			'infected last part' => [[Status::SCANRESULT_CLEAN, Status::SCANRESULT_CLEAN, Status::SCANRESULT_INFECTED], Status::SCANRESULT_INFECTED],
		];
	}

	/**
	 * @param list<int> $results
	 */
	#[DataProvider('providePartResults')]
	public function testMostSevereResultOfAllPartsIsReported(array $results, int $expected): void {
		$status = $this->scanChunks($this->getScanner($results));
		$this->assertEquals($expected, $status->getNumericStatus());
	}

	public function testFailedWriteIsReportedAsUnchecked(): void {
		$scanner = $this->getScanner([Status::SCANRESULT_CLEAN], 0);
		$status = $this->scanChunks($scanner);
		$this->assertEquals(Status::SCANRESULT_UNCHECKED, $status->getNumericStatus());
		$this->assertEquals('Failed to send the file to the antivirus scanner', $status->getDetails());
		// the scan is not continued on a new connection
		$this->assertCount(1, $scanner->parts);
	}

	public function testFailedWriteOfLaterPartIsReportedAsUnchecked(): void {
		$scanner = $this->getScanner([Status::SCANRESULT_CLEAN, Status::SCANRESULT_CLEAN], 1);
		$status = $this->scanChunks($scanner);
		$this->assertEquals(Status::SCANRESULT_UNCHECKED, $status->getNumericStatus());
		$this->assertEquals(['aaaaaaaa', ''], $scanner->parts);
	}

	public function testFailedWriteKeepsInfectedResult(): void {
		$status = $this->scanChunks($this->getScanner([Status::SCANRESULT_INFECTED, Status::SCANRESULT_CLEAN], 1));
		$this->assertEquals(Status::SCANRESULT_INFECTED, $status->getNumericStatus());
	}

	public function testUncheckedResultOfFailedWriteIsKept(): void {
		$status = $this->scanChunks($this->getScanner([Status::SCANRESULT_UNCHECKED], 0));
		$this->assertEquals(Status::SCANRESULT_UNCHECKED, $status->getNumericStatus());
		$this->assertEquals('', $status->getDetails());
	}

	public function testNewScanDoesNotKeepPreviousResult(): void {
		$scanner = $this->getScanner([Status::SCANRESULT_INFECTED, Status::SCANRESULT_CLEAN, Status::SCANRESULT_CLEAN]);
		$this->assertEquals(Status::SCANRESULT_INFECTED, $this->scanChunks($scanner)->getNumericStatus());
		$this->assertEquals(Status::SCANRESULT_CLEAN, $scanner->scanString('foo')->getNumericStatus());
	}
}
