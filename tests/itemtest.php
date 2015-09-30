<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

use OC\Files\Storage\Temporary;
use \OCA\Files_Antivirus\Item;


class Test_Files_Antivirus_Item extends \OCA\Files_Antivirus\Tests\Testbase {
	
	/**
	 * @var Temporary
	 */
	private $storage;
	
	const CONTENT = 'LoremIpsum';
	
	public function setUp() {
		parent::setUp();
		
		\OC_User::clearBackends();
		\OC_User::useBackend(new \Test\Util\User\Dummy());
		\OC\Files\Filesystem::clearMounts();

		//login
		\OC_User::createUser('test', 'test');
		\OC::$server->getSession()->set('user_id', 'test');
		
		$this->storage = new \OC\Files\Storage\Temporary(array());
		\OC\Files\Filesystem::init('test', '');
		\OC\Files\Filesystem::clearMounts();
		\OC\Files\Filesystem::mount($this->storage, array(), '/');
		\OC\Files\Filesystem::file_put_contents('file1', self::CONTENT);
		
		$this->config->method('getAvChunkSize')->willReturn('1024');
	}
	
	public function testRead() {
		$item = new Item($this->l10n, new \OC\Files\View(''), '/file1');
		$this->assertTrue($item->isValid());
		
		$chunk = $item->fread();
		$this->assertEquals(self::CONTENT, $chunk);
	}
}
