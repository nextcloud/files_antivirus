<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2021 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests\Scanner;

use OCA\Files_Antivirus\AppInfo\ConfigLexicon;
use OCA\Files_Antivirus\Scanner\ICAP;
use OCA\Files_Antivirus\Scanner\ScannerBase;
use OCA\Files_Antivirus\StatusFactory;
use OCP\ICertificateManager;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

#[Group('DB')]
class ICAPTest extends ScannerBaseTestAbstract {

	protected function getScanner(): ScannerBase {
		if (!getenv('ICAP_HOST') || !getenv('ICAP_PORT') || !getenv('ICAP_REQUEST') || !getenv('ICAP_HEADER') || !getenv('ICAP_MODE')) {
			$this->markTestSkipped('Set ICAP_HOST, ICAP_PORT, ICAP_REQUEST, ICAP_MODE and ICAP_HEADER to enable icap tests');
		}

		$logger = $this->createMock(LoggerInterface::class);
		return new ICAP($this->config, $logger, Server::get(StatusFactory::class), Server::get(ICertificateManager::class), false);
	}

	protected static function configMock(string $key): mixed {
		switch ($key) {
			case ConfigLexicon::AV_HOST:
				return getenv('ICAP_HOST');
			case ConfigLexicon::AV_PORT:
				return (int)getenv('ICAP_PORT');
			case ConfigLexicon::AV_ICAP_REQUEST_SERVICE:
				return getenv('ICAP_REQUEST');
			case ConfigLexicon::AV_ICAP_RESPONSE_HEADER:
				return getenv('ICAP_HEADER');
			case ConfigLexicon::AV_ICAP_MODE:
				return getenv('ICAP_MODE');
			case ConfigLexicon::AV_ICAP_CHUNK_SIZE:
				return 1048576;
			case ConfigLexicon::AV_ICAP_CONNECT_TIMEOUT:
				return 5;
			case ConfigLexicon::AV_ICAP_TLS:
				return getenv('ICAP_TRANSPORT') === 'tls';
			default:
				return parent::configMock($key);
		}
	}
}
