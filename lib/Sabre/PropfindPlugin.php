<?php
/**
 * @copyright 2018, Roeland Jago Douma <roeland@famdouma.nl>
 *
 * @author Roeland Jago Douma <roeland@famdouma.nl>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

namespace OCA\Files_Antivirus\Sabre;

use OCA\DAV\Upload\FutureFile;
use OCA\Files_Antivirus\AppConfig;
use OCA\Files_Antivirus\Event\ScanStateEvent;
use Sabre\DAV\Server;
use Sabre\DAV\ServerPlugin;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

class PropfindPlugin extends ServerPlugin {
	/** @var Server */
	private $server;

	/** @var AppConfig */
	private $appConfig;

	/** @var EventDispatcherInterface */
	private $eventDispatcher;


	public function __construct(AppConfig $appConfig, EventDispatcherInterface $eventDispatcher) {
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
			$this->eventDispatcher->dispatch(
				new ScanStateEvent(false)
			);
		}
	}
}
