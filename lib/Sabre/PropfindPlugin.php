<?php

/**
 * SPDX-FileCopyrightText: 2018 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Sabre;

use OCA\DAV\Upload\FutureFile;
use OCA\Files_Antivirus\AppConfig;
use OCA\Files_Antivirus\Event\ScanStateEvent;
use OCP\EventDispatcher\IEventDispatcher;
use Sabre\DAV\Server;
use Sabre\DAV\ServerPlugin;

class PropfindPlugin extends ServerPlugin {
	private Server $server;


	public function __construct(
		private readonly AppConfig $appConfig,
		private readonly IEventDispatcher $eventDispatcher,
	) {
	}

	#[\Override]
	public function initialize(Server $server): void {
		$server->on('beforeMove', [$this, 'beforeMove'], 90);
		$this->server = $server;
	}

	public function beforeMove(string $sourcePath, string $destination): void {
		$sourceNode = $this->server->tree->getNodeForPath($sourcePath);
		if (!$sourceNode instanceof FutureFile) {
			// skip handling as the source is not a chunked FutureFile
			return;
		}

		$avMaxFileSize = $this->appConfig->getAvMaxFileSize();
		if ($avMaxFileSize > -1 && $sourceNode->getSize() > $avMaxFileSize) {
			$this->eventDispatcher->dispatchTyped(
				new ScanStateEvent(false)
			);
		}
	}
}
