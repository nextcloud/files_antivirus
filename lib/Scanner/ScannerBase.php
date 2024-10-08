<?php

/**
 * SPDX-FileCopyrightText: 2017-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2012-2016 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
namespace OCA\Files_Antivirus\Scanner;

use OCA\Files_Antivirus\AppConfig;
use OCA\Files_Antivirus\Item;
use OCA\Files_Antivirus\Status;
use OCA\Files_Antivirus\StatusFactory;
use OCP\IRequest;
use Psr\Log\LoggerInterface;

abstract class ScannerBase implements IScanner {
	/**
	 * Scan result
	 */
	protected Status $status;

	/**
	 * If scanning was done part by part
	 * the first detected infected part is stored here
	 */
	protected ?Status $infectedStatus = null;

	protected int $byteCount;

	/** @var resource */
	protected $writeHandle;

	protected AppConfig $appConfig;
	protected LoggerInterface $logger;
	protected StatusFactory $statusFactory;
	protected ?string $lastChunk = null;
	protected bool $isLogUsed = false;
	protected bool $isAborted = false;
	protected string $path = '';
	protected ?IRequest $request = null;

	public function __construct(AppConfig $config, LoggerInterface $logger, StatusFactory $statusFactory) {
		$this->appConfig = $config;
		$this->logger = $logger;
		$this->statusFactory = $statusFactory;
		$this->status = $this->statusFactory->newStatus();
	}

	/**
	 * Close used resources
	 */
	abstract protected function shutdownScanner();

	/**
	 * @return Status
	 */
	public function getStatus() {
		if ($this->infectedStatus instanceof Status) {
			return $this->infectedStatus;
		}
		return $this->status;
	}

	/**
	 * Synchronous scan
	 *
	 * @param Item $item
	 * @return Status
	 */
	public function scan(Item $item): Status {
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

		$this->shutdownScanner();
		return $this->getStatus();
	}

	public function scanString(string $data): Status {
		$this->initScanner();

		$this->writeChunk($data);

		$this->shutdownScanner();
		return $this->getStatus();
	}

	/**
	 * 	 * Async scan - new portion of data is available
	 * 	 *
	 *
	 * @param string $data
	 *
	 * @return void
	 */
	public function onAsyncData($data) {
		$this->writeChunk($data);
	}

	/**
	 * Async scan - resource is closed
	 *
	 * @return Status
	 */
	public function completeAsyncScan(): Status {
		$this->shutdownScanner();
		return $this->getStatus();
	}

	/**
	 * 	 * Open write handle. etc
	 *
	 * @return void
	 */
	public function initScanner() {
		$this->byteCount = 0;
		if ($this->status->getNumericStatus() === Status::SCANRESULT_INFECTED) {
			$this->infectedStatus = clone $this->status;
		}
		$this->status = $this->statusFactory->newStatus();
	}

	/**
	 * @param string $chunk
	 *
	 * @return void
	 */
	protected function writeChunk($chunk) {
		$this->fwrite(
			$this->prepareChunk($chunk)
		);
	}

	/**
	 * @param string $data
	 *
	 * @return void
	 */
	final protected function fwrite($data) {
		if ($this->isAborted) {
			return;
		}

		$scanFirstBytes = (int)$this->appConfig->getAppValue('av_scan_first_bytes');
		if ($scanFirstBytes > -1 && $this->byteCount >= $scanFirstBytes) {
			return;
		}

		$dataLength = strlen($data);
		$streamSizeLimit = (int)$this->appConfig->getAvStreamMaxLength();
		if ($this->byteCount + $dataLength > $streamSizeLimit) {
			$this->logger->debug(
				'reinit scanner',
				['app' => 'files_antivirus']
			);
			$this->shutdownScanner();
			$isReopenSuccessful = $this->retry();
		} else {
			$isReopenSuccessful = true;
		}

		if (!$isReopenSuccessful || !$this->writeRaw($data)) {
			if (!$this->isLogUsed) {
				$this->isLogUsed = true;
				$this->logger->warning(
					'Failed to write a chunk. Check if Stream Length matches StreamMaxLength in anti virus daemon settings',
					['app' => 'files_antivirus']
				);
			}
			// retry on error
			$isRetrySuccessful = $this->retry() && $this->writeRaw($data);
			$this->isAborted = !$isRetrySuccessful;
		}
	}

	/**
	 * @return bool
	 */
	protected function retry() {
		$this->initScanner();
		if (!is_null($this->lastChunk)) {
			return $this->writeRaw($this->lastChunk);
		}
		return true;
	}

	/**
	 * @param $data
	 * @return bool
	 */
	protected function writeRaw(string $data) {
		$dataLength = strlen($data);
		$bytesWritten = @fwrite($this->getWriteHandle(), $data);
		if ($bytesWritten === $dataLength) {
			$this->byteCount += $bytesWritten;
			$this->lastChunk = $data;
			return true;
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
	 *
	 * @param string $data
	 * @return string
	 */
	protected function prepareChunk($data) {
		return $data;
	}

	public function setDebugCallback(callable $callback): void {
		// unsupported
	}

	public function setPath(string $path): void {
		$this->path = $path;
	}

	public function setRequest(IRequest $request): void {
		$this->request = $request;
	}
}
