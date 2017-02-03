<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus\Tests;

use OC\Files\Storage\Temporary;
use OCA\Files_Antivirus\Item;
use Test\Traits\MountProviderTrait;
use Test\Traits\UserTrait;

// mmm. IDK why autoloader fails on this class
include_once dirname(dirname(dirname(__DIR__))) . '/tests/lib/Util/User/Dummy.php';

/**
 * @group DB
 */
class ItemTest extends TestBase {
	use UserTrait;
	use MountProviderTrait;

	/**
	 * @var Temporary
	 */
	private $storage;
	
	const CONTENT = 'LoremIpsum';
	
	public function setUp() {
		parent::setUp();
		$this->createUser('test', 'test');
		
		$this->storage = new \OC\Files\Storage\Temporary(array());
		$this->registerMount('test', $this->storage, '/test/files');
		\OC_Util::setupFS('test');
		$view = new \OC\Files\View('/test/files');
		$view->file_put_contents('file1', self::CONTENT);
	}
	
	public function testRead() {
		$view = new \OC\Files\View('/test/files');
		$item = new Item($this->l10n, $view, '/file1');
		$this->assertTrue($item->isValid());
		
		$chunk = $item->fread();
		$this->assertEquals(self::CONTENT, $chunk);
	}
}
