<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Migration;

use Closure;
use Doctrine\DBAL\Types\Type;
use OCP\DB\ISchemaWrapper;
use OCP\DB\Schema\IColumn;
use OCP\DB\Types;
use OCP\Migration\Attributes\ColumnType;
use OCP\Migration\Attributes\ModifyColumn;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;

#[ModifyColumn(
	table: 'files_antivirus',
	name: 'fileid',
	type: ColumnType::BIGINT,
	description: 'Widen fileid to a signed bigint to match oc_filecache.fileid',
	notes: ['Inserts fail once file ids exceed the 32-bit range'],
)]
class Version60500Date20260917090000 extends SimpleMigrationStep {
	/**
	 * @param Closure(): ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function changeSchema(
		IOutput $output,
		Closure $schemaClosure,
		array $options,
	): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		// Match oc_filecache.fileid, which is a signed bigint
		$column = $schema->getTable('files_antivirus')->getColumn('fileid');
		if ($column instanceof IColumn) {
			$column->setType(Types::BIGINT);
		} else {
			// Nextcloud <35 returns a Doctrine Column, which only accepts a Type instance
			/** @psalm-suppress InvalidArgument */
			$column->setType(Type::getType(Types::BIGINT));
		}
		$column->setUnsigned(false);

		return $schema;
	}
}
