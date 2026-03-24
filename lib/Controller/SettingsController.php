<?php

/**
 * SPDX-FileCopyrightText: 2018-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2015-2016 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
namespace OCA\Files_Antivirus\Controller;

use OCA\Files_Antivirus\AppInfo\ConfigLexicon;
use OCA\Files_Antivirus\Scanner\ScannerFactory;
use OCA\Files_Antivirus\Status;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Services\IAppConfig;
use OCP\IL10N;

use OCP\IRequest;

class SettingsController extends Controller {

	public function __construct(
		string $appName,
		IRequest $request,
		private IAppConfig $appConfig,
		private IL10N $l10n,
		private ScannerFactory $scannerFactory,
		private ConfigLexicon $configLexicon,
	) {
		parent::__construct($appName, $request);
	}

	/**
	 * Save Parameters
	 *
	 * @param string $avMode - antivirus mode
	 * @param string $avSocket - path to socket (Socket mode)
	 * @param string $avHost - antivirus url
	 * @param int $avPort - port
	 * @param array $avCmdOptions - extra command line options
	 * @param string $avPath - path to antivirus executable (Executable mode)
	 * @param string $avInfectedAction - action performed on infected files
	 * @param bool $avBlockUnreachable - block upload if scanner not reachable
	 * @param int $avStreamMaxLength - reopen socket after bytes
	 * @param int $avMaxFileSize - file size limit
	 * @param int $avScanFirstBytes - scan size limit
	 * @param string $avIcapMode
	 * @param bool $avIcapTls
	 * @param bool $avBlockUnscannable
	 * @return JSONResponse
	 */
	public function save(
		string $avMode,
		string $avSocket,
		string $avHost,
		int $avPort,
		array $avCmdOptions,
		string $avPath,
		string $avInfectedAction,
		int $avStreamMaxLength,
		int $avMaxFileSize,
		int $avScanFirstBytes,
		bool $avBlockUnreachable,
		bool $avBlockUnscannable,
		bool $avIcapTls,
		string $avIcapMode,
		string $avIcapRequestService,
		string $avIcapResponseHeader,
	) {
		if (!array_all($avCmdOptions, fn ($value) => is_string($value))) {
			return new JSONResponse(['message' => 'Command options must be an array of strings'], Http::STATUS_BAD_REQUEST);
		}

		$this->appConfig->setAppValueString(ConfigLexicon::AV_MODE, $avMode);
		$this->appConfig->setAppValueString(ConfigLexicon::AV_SOCKET, $avSocket);
		$this->appConfig->setAppValueString(ConfigLexicon::AV_HOST, $avHost);
		$this->appConfig->setAppValueArray(ConfigLexicon::AV_CMD_OPTIONS, $avCmdOptions);
		$this->appConfig->setAppValueString(ConfigLexicon::AV_PATH, $avPath);
		$this->appConfig->setAppValueString(ConfigLexicon::AV_INFECTED_ACTION, $avInfectedAction);
		$this->appConfig->setAppValueInt(ConfigLexicon::AV_PORT, $avPort);
		$this->appConfig->setAppValueInt(ConfigLexicon::AV_STREAM_MAX_LENGTH, $avStreamMaxLength);
		$this->appConfig->setAppValueInt(ConfigLexicon::AV_MAX_FILE_SIZE, $avMaxFileSize);
		$this->appConfig->setAppValueInt(ConfigLexicon::AV_SCAN_FIRST_BYTES, $avScanFirstBytes);
		$this->appConfig->setAppValueBool(ConfigLexicon::AV_BLOCK_UNSCANNABLE, $avBlockUnscannable);
		$this->appConfig->setAppValueBool(ConfigLexicon::AV_BLOCK_UNREACHABLE, $avBlockUnreachable);
		$this->appConfig->setAppValueBool(ConfigLexicon::AV_ICAP_TLS, $avIcapTls);
		$this->appConfig->setAppValueString(ConfigLexicon::AV_ICAP_MODE, $avIcapMode);
		$this->appConfig->setAppValueString(ConfigLexicon::AV_ICAP_REQUEST_SERVICE, $avIcapRequestService);
		$this->appConfig->setAppValueString(ConfigLexicon::AV_ICAP_RESPONSE_HEADER, $avIcapResponseHeader);

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
			['data'
				=> ['message' => $message],
				'status' => $success ? 'success' : 'error',
				'settings' => $this->configLexicon->getAllConfigValues(),
			]
		);
	}
}
