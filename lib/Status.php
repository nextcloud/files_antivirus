<?php
/**
 * Copyright (c) 2014 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus;

use OCA\Files_Antivirus\Db\Rule;
use OCA\Files_Antivirus\Db\RuleMapper;
use Psr\Log\LoggerInterface;

class Status {
	/*
	 *  The file was not checked (e.g. because the AV daemon wasn't running).
	 */
	public const SCANRESULT_UNCHECKED = -1;

	/*
	 *  The file was checked and found to be clean.
	 */
	public const SCANRESULT_CLEAN = 0;

	/*
	 *  The file was checked and found to be infected.
	 */
	public const SCANRESULT_INFECTED = 1;

	/*
	 * Should be SCANRESULT_UNCHECKED | SCANRESULT_INFECTED | SCANRESULT_CLEAN
	 */
	protected $numericStatus = self::SCANRESULT_UNCHECKED;

	/*
	 * Virus name or error message
	 */
	protected $details = '';

	protected RuleMapper $ruleMapper;
	protected LoggerInterface $logger;

	public function __construct(RuleMapper $ruleMapper, LoggerInterface $logger) {
		$this->ruleMapper = $ruleMapper;
		$this->logger = $logger;
	}

	/**
	 * Get scan status as integer
	 * @return int
	 */
	public function getNumericStatus(): int {
		return $this->numericStatus;
	}

	/**
	 * Get scan status as string
	 * @return string
	 */
	public function getDetails() {
		return $this->details;
	}

	public function setNumericStatus(int $numericStatus): void {
		$this->numericStatus = $numericStatus;
	}

	public function setDetails(string $details): void {
		$this->details = $details;
	}

	/**
	 * @param string $rawResponse
	 * @param integer $result
	 *
	 * @return void
	 */
	public function parseResponse($rawResponse, $result = null) {
		$matches = [];

		if (is_null($result)) { // Daemon or socket mode
			try {
				$allRules = $this->getResponseRules();
			} catch (\Exception $e) {
				$this->logger->error(__METHOD__.', exception: '.$e->getMessage(), ['app' => 'files_antivirus']);
				return;
			}

			$isMatched = false;
			foreach ($allRules as $rule) {
				if (preg_match($rule->getMatch(), $rawResponse, $matches)) {
					$isMatched = true;
					$this->numericStatus = (int)$rule->getStatus();
					if ((int)$rule->getStatus() === self::SCANRESULT_CLEAN) {
						$this->details = '';
					} else {
						$this->details = isset($matches[1]) ? $matches[1] : 'unknown';
					}
					break;
				}
			}

			if (!$isMatched) {
				$this->numericStatus = self::SCANRESULT_UNCHECKED;

				// Adding the ASCII text range 32..126 (excluding '`') of the raw socket response to the details.
				$response = filter_var($rawResponse, FILTER_UNSAFE_RAW, FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH | FILTER_FLAG_STRIP_BACKTICK);
				if (strlen($response) > 512) {
					$response = substr($response, 0, 509) . "...";
				}
				$this->details = 'No matching rule for response [' . $response . ']. Please check antivirus rules configuration.';
			}
		} else { // Executable mode
			$scanStatus = $this->ruleMapper->findByResult($result);
			if (is_array($scanStatus) && count($scanStatus)) {
				$this->numericStatus = (int)$scanStatus[0]->getStatus();
				$this->details = $scanStatus[0]->getDescription();
			}

			switch ($this->numericStatus) {
				case self::SCANRESULT_INFECTED:
					$report = [];
					$rawResponse = explode("\n", $rawResponse);

					foreach ($rawResponse as $line) {
						if (preg_match('/.*: (.*) FOUND\s*$/', $line, $matches)) {
							$report[] = $matches[1];
						}
					}
					$this->details = implode(', ', $report);

					break;
				case self::SCANRESULT_UNCHECKED:
					if (!$this->details) {
						$this->details = 'No matching rule for exit code ' .  $this->numericStatus .'. Please check antivirus rules configuration.' ;
					}
			}
		}
	}

	/**
	 * @return Rule[]
	 */
	protected function getResponseRules() {
		$infectedRules = $this->ruleMapper->findAllMatchedByStatus(self::SCANRESULT_INFECTED);
		$uncheckedRules = $this->ruleMapper->findAllMatchedByStatus(self::SCANRESULT_UNCHECKED);
		$cleanRules = $this->ruleMapper->findAllMatchedByStatus(self::SCANRESULT_CLEAN);

		$infectedRules = $infectedRules ? $infectedRules : [];
		$uncheckedRules = $uncheckedRules ? $uncheckedRules : [];
		$cleanRules = $cleanRules ? $cleanRules : [];

		// order: clean, infected, try to guess error
		return array_merge($cleanRules, $infectedRules, $uncheckedRules);
	}

	public function dispatch(Item $item): void {
		switch ($this->getNumericStatus()) {
			case self::SCANRESULT_UNCHECKED:
				$item->processUnchecked($this);
				break;
			case self::SCANRESULT_INFECTED:
				$item->processInfected($this);
				break;
			case self::SCANRESULT_CLEAN:
				$item->processClean();
				break;
		}
	}
}
