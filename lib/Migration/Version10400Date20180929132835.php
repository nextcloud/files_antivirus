<?php
/**
 * @copyright Copyright (c) 2018 Roeland Jago Douma <roeland@famdouma.nl>
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

namespace OCA\Files_Antivirus\Migration;

use Closure;
use OCP\DB\ISchemaWrapper;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;

class Version10400Date20180929132835 extends SimpleMigrationStep {
	/**
	 * @param IOutput $output
	 * @param Closure $schemaClosure The `\Closure` returns a `ISchemaWrapper`
	 * @param array $options
	 * @return null|ISchemaWrapper
	 */
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options) {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		if (!$schema->hasTable('files_antivirus')) {
			$table = $schema->createTable('files_antivirus');
			$table->addColumn('fileid', 'integer', [
				'notnull' => true,
				'length' => 4,
				'unsigned' => true,
			]);
			$table->addColumn('check_time', 'integer', [
				'notnull' => true,
				'length' => 4,
				'default' => 0,
				'unsigned' => true,
			]);
			$table->setPrimaryKey(['fileid']);
		}

		if (!$schema->hasTable('files_avir_status')) {
			$table = $schema->createTable('files_avir_status');
			$table->addColumn('id', 'integer', [
				'autoincrement' => true,
				'notnull' => true,
				'length' => 4,
				'unsigned' => true,
			]);
			$table->addColumn('group_id', 'integer', [
				'notnull' => true,
				'length' => 4,
				'default' => 0,
				'unsigned' => true,
			]);
			$table->addColumn('status_type', 'integer', [
				'notnull' => true,
				'length' => 4,
				'default' => 0,
				'unsigned' => true,
			]);
			$table->addColumn('result', 'integer', [
				'notnull' => true,
				'length' => 4,
				'default' => 0,
			]);
			$table->addColumn('match', 'string', [
				'notnull' => false,
				'length' => 64,
			]);
			$table->addColumn('description', 'string', [
				'notnull' => false,
				'length' => 64,
			]);
			$table->addColumn('status', 'integer', [
				'notnull' => true,
				'length' => 4,
				'default' => 0,
			]);
			$table->setPrimaryKey(['id']);
		}
		return $schema;
	}
}
