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
	/** @var Server */
	private $server;

	/** @var AppConfig */
	private $appConfig;

	/** @var IEventDispatcher */
	private $eventDispatcher;


	public function __construct(AppConfig $appConfig, IEventDispatcher $eventDispatcher) {
		$this->appConfig = $appConfig;
		$this->eventDispatcher = $eventDispatcher;
	}

	/**
	 * @return void
	 */
	public function initialize(Server $server) {
		$server->on('beforeMove', [$this, 'beforeMove'], 90);
		$this->server = $server;
	}

	/**
	 * @param string $sourcePath source path
	 * @param string $destination destination path
	 *
	 * @return void
	 */
	public function beforeMove($sourcePath, $destination) {
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
