<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\Cron;

use OCA\Files_Antivirus\Db\Rule;

class Test_Files_Antivirus_Db_RuleTest extends \OCA\Files_Antivirus\Tests\Testbase {
	public function testJsonSerialize(){
		$data = [
			'groupId' => 0,
			'statusType' => Rule::RULE_TYPE_CODE,
			'result' => 0,
			'match' => '',
			'description' => "",
			'status' => \OCA\Files_Antivirus\Status::SCANRESULT_CLEAN
		];
		$expected = [
			'group_id' => 0,
			'status_type' => Rule::RULE_TYPE_CODE,
			'result' => 0,
			'match' => '',
			'description' => "",
			'status' => \OCA\Files_Antivirus\Status::SCANRESULT_CLEAN
		];
		
		$rule = Rule::fromParams($data);
		$this->assertEquals(
				$expected,
				$rule->jsonSerialize()
		);
	}
}
