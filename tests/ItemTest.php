<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_antivirus\Tests;

use OC\Files\Storage\Temporary;
use OCA\Files_Antivirus\Item;

// mmm. IDK why autoloader fails on this class
include_once dirname(dirname(dirname(__DIR__))) . '/tests/lib/Util/User/Dummy.php';

class ItemTest extends TestBase {
	
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
		\OC::$server->getUserManager()->createUser('test', 'test');
		\OC::$server->getUserSession()->login('test', 'test');
		\OC::$server->getSession()->set('user_id', 'test');
		\OC::$server->getUserFolder('test');
		\OC_Util::setupFS('test');
		
		$this->storage = new \OC\Files\Storage\Temporary(array());
		\OC\Files\Filesystem::init('test', '');
		$view = new \OC\Files\View('/test/files');
		$view->file_put_contents('file1', self::CONTENT);
		$this->config->method('__call')
			->with(
				$this->equalTo('getAvChunkSize')
			)
			->willReturn('1024')
		;
	}
	
	public function testRead() {
		$view = new \OC\Files\View('/test/files');
		$item = new Item($this->l10n, $view, '/file1');
		$this->assertTrue($item->isValid());
		
		$chunk = $item->fread();
		$this->assertEquals(self::CONTENT, $chunk);
	}
}
