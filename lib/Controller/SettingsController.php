<?php

/**
 * SPDX-FileCopyrightText: 2018-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2015-2016 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
namespace OCA\Files_Antivirus\Controller;

use OCA\Files_Antivirus\AppConfig;
use OCA\Files_Antivirus\Scanner\ScannerFactory;
use OCA\Files_Antivirus\Status;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\JSONResponse;
use OCP\IL10N;

use OCP\IRequest;

class SettingsController extends Controller {
	/**
	 * @var AppConfig
	 */
	private $settings;

	/**
	 * @var IL10N
	 */
	private $l10n;

	private $scannerFactory;

	public function __construct($appName, IRequest $request, AppConfig $appconfig, IL10N $l10n, ScannerFactory $scannerFactory) {
		parent::__construct($appName, $request);

		$this->settings = $appconfig;
		$this->l10n = $l10n;
		$this->scannerFactory = $scannerFactory;
	}

	/**
	 * Save Parameters
	 *
	 * @param string $avMode - antivirus mode
	 * @param string $avSocket - path to socket (Socket mode)
	 * @param string $avHost - antivirus url
	 * @param int $avPort - port
	 * @param string $avCmdOptions - extra command line options
	 * @param string $avPath - path to antivirus executable (Executable mode)
	 * @param string $avInfectedAction - action performed on infected files
	 * @param string $avBlockUnreachable - block upload if scanner not reachable
	 * @param $avStreamMaxLength - reopen socket after bytes
	 * @param int $avMaxFileSize - file size limit
	 * @param int $avScanFirstBytes - scan size limit
	 * @param string $avIcapMode
	 * @param bool $avIcapTls
	 * @param bool $avBlockUnscannable
	 * @return JSONResponse
	 */
	public function save(
		$avMode,
		$avSocket,
		$avHost,
		$avPort,
		$avCmdOptions,
		$avPath,
		$avInfectedAction,
		$avBlockUnreachable,
		$avStreamMaxLength,
		$avMaxFileSize,
		$avScanFirstBytes,
		$avIcapMode,
		$avIcapRequestService,
		$avIcapResponseHeader,
		$avIcapTls,
		$avBlockUnscannable
	) {
		$this->settings->setAvMode($avMode);
		$this->settings->setAvSocket($avSocket);
		$this->settings->setAvHost($avHost);
		$this->settings->setAvPort($avPort);
		$this->settings->setAvCmdOptions($avCmdOptions);
		$this->settings->setAvPath($avPath);
		$this->settings->setAvInfectedAction($avInfectedAction);
		$this->settings->setAvStreamMaxLength($avStreamMaxLength);
		$this->settings->setAvMaxFileSize($avMaxFileSize);
		$this->settings->setAvScanFirstBytes($avScanFirstBytes);
		$this->settings->setAvIcapMode($avIcapMode);
		$this->settings->setAvIcapRequestService($avIcapRequestService);
		$this->settings->setAvIcapResponseHeader($avIcapResponseHeader);
		$this->settings->setAvIcapTls((bool)$avIcapTls);
		$this->settings->setAvBlockUnscannable((bool)$avBlockUnscannable);
		$this->settings->setAvBlockUnreachable($avBlockUnreachable);

		try {
			$scanner = $this->scannerFactory->getScanner('/self-test.txt');
			$result = $scanner->scanString('dummy scan content');
			$success = $result->getNumericStatus() == Status::SCANRESULT_CLEAN;
			$message = $success ? $this->l10n->t('Saved') : 'unexpected scan results for test content';
		} catch (\Exception $e) {
			$message = $e->getMessage();
			$success = false;
		}

		return new JSONResponse(
			['data' =>
				['message' => $message],
				'status' => $success ? 'success' : 'error',
				'settings' => $this->settings->getAllValues(),
			]
		);
	}
}
