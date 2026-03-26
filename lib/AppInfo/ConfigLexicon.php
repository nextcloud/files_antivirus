<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\AppInfo;

use OCA\Files_Antivirus\ICAP\ICAPClient;
use OCP\Config\Lexicon\Entry;
use OCP\Config\Lexicon\ILexicon;
use OCP\Config\Lexicon\Strictness;
use OCP\Config\ValueType;
use OCP\IAppConfig;
use OCP\Server;
use Override;

class ConfigLexicon implements ILexicon {

	public const AV_MODE = 'av_mode';
	public const AV_SOCKET = 'av_socket';
	public const AV_HOST = 'av_host';
	public const AV_PORT = 'av_port';
	public const AV_CMD_OPTIONS = 'av_cmd_options';
	public const AV_PATH = 'av_path';
	public const AV_INFECTED_ACTION = 'av_infected_action';
	public const AV_BLOCK_UNREACHABLE = 'av_block_unreachable';
	public const AV_STREAM_MAX_LENGTH = 'av_stream_max_length';
	public const AV_MAX_FILE_SIZE = 'av_max_file_size';
	public const AV_SCAN_FIRST_BYTES = 'av_scan_first_bytes';
	public const AV_ICAP_MODE = 'av_icap_mode';
	public const AV_ICAP_TLS = 'av_icap_tls';
	public const AV_ICAP_REQUEST_SERVICE = 'av_icap_request_service';
	public const AV_ICAP_RESPONSE_HEADER = 'av_icap_response_header';
	public const AV_ICAP_CHUNK_SIZE = 'av_icap_chunk_size';
	public const AV_ICAP_CONNECT_TIMEOUT = 'av_icap_connect_timeout';
	public const AV_BLOCK_UNSCANNABLE = 'av_block_unscannable';
	public const AV_BLOCKLISTED_DIRECTORIES = 'av_blocklisted_directories';
	public const AV_BACKGROUND_SCAN = 'av_background_scan';

	#[Override]
	public function getStrictness(): Strictness {
		return Strictness::WARNING;
	}

	#[Override]
	public function getAppConfigs(): array {
		return [
			new Entry(
				key: self::AV_MODE,
				type: ValueType::STRING,
				defaultRaw: 'executable',
				definition: 'Antivirus mode. Available modes are "daemon", "socket", "executable", "kaspersky" and "icap".',
			),
			new Entry(
				key: self::AV_SOCKET,
				type: ValueType::STRING,
				defaultRaw: '/var/run/clamav/clamd.ctl',
				definition: 'Path to socket for socket mode',
			),
			new Entry(
				key: self::AV_HOST,
				type: ValueType::STRING,
				defaultRaw: '',
				definition: 'Host for daemon, Kaspersky and ICAP mode',
			),
			new Entry(
				key: self::AV_PORT,
				type: ValueType::INT,
				defaultRaw: 3310,
				definition: 'Port for daemon, Kaspersky and ICAP mode',
			),
			new Entry(
				key: self::AV_PATH,
				type: ValueType::STRING,
				defaultRaw: '/usr/bin/clamscan',
				definition: 'Path to antivirus executable for executable mode',
			),
			new Entry(
				key: self::AV_CMD_OPTIONS,
				type: ValueType::ARRAY,
				defaultRaw: [],
				definition: 'Extra command line options for executable mode',
			),
			new Entry(
				key: self::AV_INFECTED_ACTION,
				type: ValueType::STRING,
				defaultRaw: 'only_log',
				definition: 'Action performed on infected files. Available actions are "only_log" and "delete".',
			),
			new Entry(
				key: self::AV_BLOCK_UNREACHABLE,
				type: ValueType::BOOL,
				defaultRaw: true,
				definition: 'Block upload if scanner not reachable.',
			),
			new Entry(
				key: self::AV_BLOCK_UNSCANNABLE,
				type: ValueType::BOOL,
				defaultRaw: false,
				definition: 'Block upload if file cannot be scanned.',
			),
			new Entry(
				key: self::AV_BLOCKLISTED_DIRECTORIES,
				type: ValueType::ARRAY,
				defaultRaw: [],
				definition: 'List of directories that should not be scanned.',
			),
			new Entry(
				key: self::AV_BACKGROUND_SCAN,
				type: ValueType::BOOL,
				defaultRaw: true,
				definition: 'Whether to scan files in background after upload or scan them during upload.',
			),
			new Entry(
				key: self::AV_STREAM_MAX_LENGTH,
				type: ValueType::INT,
				defaultRaw: 26214400,
				definition: 'Reopen socket after bytes written.',
			),
			new Entry(
				key: self::AV_MAX_FILE_SIZE,
				type: ValueType::INT,
				defaultRaw: -1,
				definition: 'Maximum file size that can be scanned.',
			),
			new Entry(
				key: self::AV_SCAN_FIRST_BYTES,
				type: ValueType::INT,
				defaultRaw: -1,
				definition: 'Number of first bytes to scan.',
			),
			new Entry(
				key: self::AV_ICAP_MODE,
				type: ValueType::STRING,
				defaultRaw: ICAPClient::MODE_REQ_MOD,
				definition: 'ICAP mode. Available modes are "req_mod" and "resp_mod".',
			),
			new Entry(
				key: self::AV_ICAP_TLS,
				type: ValueType::BOOL,
				defaultRaw: false,
				definition: 'Whether to use TLS for ICAP connection.',
			),
			new Entry(
				key: self::AV_ICAP_REQUEST_SERVICE,
				type: ValueType::STRING,
				defaultRaw: 'avscan',
				definition: 'ICAP request service.',
			),
			new Entry(
				key: self::AV_ICAP_RESPONSE_HEADER,
				type: ValueType::STRING,
				defaultRaw: 'X-Infection-Found',
				definition: 'ICAP response header that indicates an infection.',
			),
			new Entry(
				key: self::AV_ICAP_CHUNK_SIZE,
				type: ValueType::INT,
				defaultRaw: 1048576,
				definition: 'Chunk size for ICAP requests.',
			),
			new Entry(
				key: self::AV_ICAP_CONNECT_TIMEOUT,
				type: ValueType::INT,
				defaultRaw: 5,
				definition: 'Connection timeout for ICAP requests in seconds.',
			),
		];
	}

	#[Override]
	public function getUserConfigs(): array {
		return [];
	}

	public function getAllConfigValues(): array {
		$appConfig = Server::get(IAppConfig::class);
		$entires = $this->getAppConfigs();
		$config = [];
		foreach ($entires as $entry) {
			switch ($entry->getValueType()) {
				case ValueType::BOOL:
					$value = $appConfig->getValueBool(Application::APP_NAME, $entry->getKey());
					break;
				case ValueType::INT:
					$value = $appConfig->getValueInt(Application::APP_NAME, $entry->getKey());
					break;
				case ValueType::ARRAY:
					$value = $appConfig->getValueArray(Application::APP_NAME, $entry->getKey());
					break;
				default:
					$value = $appConfig->getValueString(Application::APP_NAME, $entry->getKey());
			}
			$config[$this->camelCase($entry->getKey())] = $value;
		}
		return $config;
	}

	/**
	 * Translates property_name into propertyName
	 */
	private function camelCase(string $property): string {
		$split = explode('_', $property);
		$ucFirst = implode('', array_map(ucfirst(...), $split));
		return lcfirst($ucFirst);
	}
}
