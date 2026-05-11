<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Listener;

use OCA\Files_Antivirus\Db\Item;
use OCA\Files_Antivirus\Db\ItemMapper;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\Files\Events\Node\NodeWrittenEvent;
use OCP\Files\File;
use Psr\Log\LoggerInterface;

/** @template-implements IEventListener<NodeWrittenEvent> */
class NodeWrittenListener implements IEventListener {
	public function __construct(
		private readonly ItemMapper $itemMapper,
		private readonly ITimeFactory $timeFactory,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof NodeWrittenEvent) {
			return;
		}

		$node = $event->getNode();
		if (!$node instanceof File) {
			return;
		}

		// Mark file as scanned after upload completes
		try {
			$this->markFileAsScanned($node->getId());
		} catch (\Exception $e) {
			$this->logger->warning('Failed to mark uploaded file as scanned: ' . $e->getMessage(), [
				'app' => 'files_antivirus',
				'fileId' => $node->getId(),
				'exception' => $e,
			]);
		}
	}

	private function markFileAsScanned(int $fileId): void {
		try {
			$existing = $this->itemMapper->findByFileId($fileId);
			$this->itemMapper->delete($existing);
		} catch (DoesNotExistException) {
			// No existing entry, that's fine
		}

		$item = new Item();
		$item->setFileid($fileId);
		$item->setCheckTime($this->timeFactory->getTime());
		$this->itemMapper->insert($item);
	}
}
