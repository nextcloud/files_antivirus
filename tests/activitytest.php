<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\Cron;

use OCA\Files_Antivirus\Activity;

class Test_Files_Antivirus_ActivityTest extends \OCA\Files_Antivirus\Tests\Testbase {
	protected $activity;
	
	public function setUp(){
		parent::setUp();
		$langFactory = $this->getMockBuilder('OC\L10N\Factory')
				->disableOriginalConstructor()
				->getMock()
		;
		
		$urlGenerator = $this->getMockBuilder('OCP\IURLGenerator')
				->disableOriginalConstructor()
				->getMock()
		;
		
		$this->activity = new Activity($langFactory, $urlGenerator);
	}
	
	public function testGetTypeIcon(){
		$this->assertFalse(
				$this->activity->getTypeIcon(null)
		);
		
		$this->assertEquals('icon-info', $this->activity->getTypeIcon(Activity::TYPE_VIRUS_DETECTED) );
	}
	
	public function testGetSpecialParameterList(){
		$this->assertFalse(
				$this->activity->getSpecialParameterList(null, null)
		);
	}
	
	public function testGetGroupParameter(){
		$this->assertFalse(
				$this->activity->getGroupParameter(null)
		);
	}
}
