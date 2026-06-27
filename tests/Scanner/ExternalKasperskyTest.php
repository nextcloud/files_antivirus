<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2021 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests\Scanner;

use OCA\Files_Antivirus\AppInfo\ConfigLexicon;
use OCA\Files_Antivirus\Scanner\ExternalKaspersky;
use OCA\Files_Antivirus\Scanner\ScannerBase;
use OCA\Files_Antivirus\StatusFactory;
use OCP\Http\Client\IClientService;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

#[Group('DB')]
class ExternalKasperskyTest extends ScannerBaseTestAbstract {
	protected function getScanner(): ScannerBase {
		if (!getenv('KASPERSKY_HOST') || !getenv('KASPERSKY_PORT')) {
			$this->markTestSkipped('Set KASPERSKY_HOST and KASPERSKY_PORT to enable kaspersky tests');
		}

		$logger = $this->createMock(LoggerInterface::class);
		return new ExternalKaspersky($this->config, $logger, Server::get(StatusFactory::class), Server::get(IClientService::class));
	}

	protected static function configMock(string $key): mixed {
		switch ($key) {
			case ConfigLexicon::AV_HOST:
				return getenv('KASPERSKY_HOST');
			case ConfigLexicon::AV_PORT:
				return (int)getenv('KASPERSKY_PORT');
			default:
				return parent::configMock($key);
		}
	}
}
