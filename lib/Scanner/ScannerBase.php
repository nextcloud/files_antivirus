<?php

/**
 * SPDX-FileCopyrightText: 2017-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2012-2016 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Scanner;

use OCA\Files_Antivirus\AppInfo\ConfigLexicon;
use OCA\Files_Antivirus\Item;
use OCA\Files_Antivirus\Status;
use OCA\Files_Antivirus\StatusFactory;
use OCP\AppFramework\Services\IAppConfig;
use OCP\IRequest;
use Psr\Log\LoggerInterface;

abstract class ScannerBase implements IScanner {
	/**
	 * Severity of the scan results, the most severe result of all parts of a file is reported
	 */
	private const STATUS_SEVERITY = [
		Status::SCANRESULT_CLEAN => 0,
		Status::SCANRESULT_UNSCANNABLE => 1,
		Status::SCANRESULT_UNCHECKED => 2,
		Status::SCANRESULT_INFECTED => 3,
	];

	/**
	 * Scan result of the current part
	 */
	protected Status $status;

	/**
	 * If scanning was done part by part
	 * the most severe result of all parts before the current one is stored here
	 */
	protected ?Status $mostSevereStatus = null;

	protected int $byteCount;

	/** @var resource */
	protected $writeHandle;

	protected ?string $lastChunk = null;
	/** Set if data could not be written to the scanner, the file is then reported as unchecked */
	protected bool $isAborted = false;
	protected string $path = '';
	protected ?int $size = null;
	protected ?IRequest $request = null;
	private ?string $ignoreRegex;

	public function __construct(
		protected readonly IAppConfig $appConfig,
		protected readonly LoggerInterface $logger,
		private readonly StatusFactory $statusFactory,
	) {
		$this->status = $this->statusFactory->newStatus();
		$this->ignoreRegex = $this->appConfig->getAppValue('av_ignore_path_regex');
	}

	/**
	 * Close used resources
	 */
	abstract protected function shutdownScanner(): void;

	#[\Override]
	public function getStatus(): Status {
		if ($this->mostSevereStatus !== null
			&& self::getSeverity($this->mostSevereStatus) >= self::getSeverity($this->status)) {
			return $this->mostSevereStatus;
		}
		return $this->status;
	}

	/**
	 * Unknown results are handled like unchecked ones
	 */
	private static function getSeverity(Status $status): int {
		return self::STATUS_SEVERITY[$status->getNumericStatus()] ?? self::STATUS_SEVERITY[Status::SCANRESULT_UNCHECKED];
	}

	/**
	 * Synchronous scan
	 *
	 * @param Item $item
	 * @return Status
	 */
	#[\Override]
	public function scan(Item $item): Status {
		if ($this->ignoreRegex && preg_match($this->ignoreRegex, $item->getFilePath()) === 1) {
			$this->status->setNumericStatus(Status::SCANRESULT_IGNORE);
			return $this->getStatus();
		}

		$this->initScanner();

		try {
			while (false !== ($chunk = $item->fread())) {
				$this->writeChunk($chunk);
			}
		} catch (\OCP\Encryption\Exceptions\GenericEncryptionException $e) {
			// We can't read the file, ignore
			$this->shutdownScanner();
			$this->status->setNumericStatus(Status::SCANRESULT_CLEAN);
			return $this->getStatus();
		}

		return $this->finishScan();
	}

	#[\Override]
	public function scanString(string $data): Status {
		$this->initScanner();

		$this->writeChunk($data);

		return $this->finishScan();
	}

	/**
	 * Async scan - new portion of data is available
	 */
	#[\Override]
	public function onAsyncData(string $data): void {
		$this->writeChunk($data);
	}

	/**
	 * Async scan - resource is closed
	 *
	 * @return Status
	 */
	#[\Override]
	public function completeAsyncScan(): Status {
		return $this->finishScan();
	}

	/**
	 * Get the result of the scanner and report the file as unchecked
	 * if not all data could be sent to the scanner.
	 */
	private function finishScan(): Status {
		$this->shutdownScanner();
		$numericStatus = $this->status->getNumericStatus();
		if ($this->isAborted && $numericStatus !== Status::SCANRESULT_INFECTED) {
			$details = 'Failed to send the file to the antivirus scanner, check that Stream Length is below the scanner\'s StreamMaxLength';
			$scannerDetails = trim((string)$this->status->getDetails());
			$this->status->setNumericStatus(Status::SCANRESULT_UNCHECKED);
			$this->status->setDetails($scannerDetails === '' ? $details : $details . ' (' . $scannerDetails . ')');
		}
		return $this->getStatus();
	}

	/**
	 * Open write handle. etc
	 */
	#[\Override]
	public function initScanner(): void {
		$this->byteCount = 0;
		$this->lastChunk = null;
		$this->isAborted = false;
		$this->mostSevereStatus = null;
		$this->status = $this->statusFactory->newStatus();
	}

	protected function writeChunk(string $chunk): void {
		$this->fwrite(
			$this->prepareChunk($chunk)
		);
	}

	final protected function fwrite(string $data): void {
		if ($this->isAborted) {
			return;
		}

		$scanFirstBytes = $this->appConfig->getAppValueInt(ConfigLexicon::AV_SCAN_FIRST_BYTES);
		if ($scanFirstBytes > -1 && $this->byteCount >= $scanFirstBytes) {
			return;
		}

		$dataLength = strlen($data);
		$streamSizeLimit = $this->appConfig->getAppValueInt(ConfigLexicon::AV_STREAM_MAX_LENGTH);
		if ($this->byteCount + $dataLength > $streamSizeLimit) {
			$this->logger->debug(
				'reinit scanner',
				['app' => 'files_antivirus']
			);
			$this->shutdownScanner();
			$isReopenSuccessful = $this->reinitScanner();
		} else {
			$isReopenSuccessful = true;
		}

		// The data already sent to the scanner is lost when a write fails (e.g. the daemon closed the connection
		// because its StreamMaxLength was reached), so the scan cannot be resumed on a new connection.
		if (!$isReopenSuccessful || !$this->writeRaw($data)) {
			$this->isAborted = true;
			$this->logger->warning(
				'Failed to write a chunk, the file is reported as unchecked. Check if Stream Length matches StreamMaxLength in anti virus daemon settings',
				['app' => 'files_antivirus']
			);
		}
	}

	/**
	 * Start the scan of the next part of the file,
	 * it begins with the last chunk of the previous part.
	 */
	private function reinitScanner(): bool {
		$mostSevereStatus = $this->getStatus();
		$lastChunk = $this->lastChunk;
		$this->initScanner();
		$this->mostSevereStatus = $mostSevereStatus;
		return $lastChunk === null || $this->writeRaw($lastChunk);
	}

	protected function writeRaw(string $data): bool {
		$dataLength = strlen($data);
		$bytesWritten = @fwrite($this->getWriteHandle(), $data);
		if ($bytesWritten === $dataLength) {
			$this->byteCount += $bytesWritten;
			$this->lastChunk = $data;
			return true;
		} else {
			$this->logger->warning("tried to write $dataLength bytes to antivirus but only managed to write $bytesWritten bytes.");
		}
		return false;
	}

	/**
	 * Get a resource to write data into
	 *
	 * @return resource
	 */
	protected function getWriteHandle() {
		return $this->writeHandle;
	}

	/**
	 * Prepare chunk (if required)
	 */
	protected function prepareChunk(string $data): string {
		return $data;
	}

	#[\Override]
	public function setDebugCallback(callable $callback): void {
		// unsupported
	}

	public function setPath(string $path): void {
		$this->path = $path;
	}

	public function setSize(int $size): void {
		$this->size = $size;
	}

	public function setRequest(IRequest $request): void {
		$this->request = $request;
	}
}
