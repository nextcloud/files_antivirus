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

use OCA\Files_Antivirus\Db\RuleMapper;
use OCP\IConfig;
use OCP\Migration\IOutput;
use OCP\Migration\IRepairStep;

class Install implements IRepairStep {
	/** @var RuleMapper */
	private $ruleMapper;

	/** @var IConfig */
	private $config;

	public function __construct(RuleMapper $ruleMapper, IConfig $config) {
		$this->ruleMapper = $ruleMapper;
		$this->config = $config;
	}

	public function getName() {
		return 'Populare default rules';
	}

	/**
	 * @return void
	 */
	public function run(IOutput $output) {
		$rules = $this->ruleMapper->findAll();

		if ($rules === []) {
			$this->ruleMapper->populate();
		}

		$this->config->setAppValue('files_antivirus', 'av_path', '/usr/bin/clamscan');
	}
}
