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

namespace OCA\Files_Antivirus;

use OCA\Files_Antivirus\Db\RuleMapper;
use Psr\Log\LoggerInterface;

class StatusFactory {
	private RuleMapper $ruleMapper;
	private LoggerInterface $logger;

	public function __construct(RuleMapper $ruleMapper, LoggerInterface $logger) {
		$this->ruleMapper = $ruleMapper;
		$this->logger = $logger;
	}

	public function newStatus(): Status {
		return new Status(
			$this->ruleMapper,
			$this->logger
		);
	}
}
