<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_antivirus\Tests;

use OC\Files\Filesystem;
use OC\Files\View;
use OCA\Files_Antivirus\Item;

// mmm. IDK why autoloader fails on this class
include_once dirname(dirname(dirname(__DIR__))) . '/tests/lib/Util/User/Dummy.php';

class ItemTest extends TestBase {

	const UID = 'testo';
	const PWD = 'test';
	const CONTENT = 'LoremIpsum';

	protected $view;

	public static function setUpBeforeClass() {
		parent::setUpBeforeClass();
		\OC_User::clearBackends();
		\OC_User::useBackend(new \Test\Util\User\Dummy());
	}

	public function setUp() {
		parent::setUp();

		//login
		if (!\OC::$server->getUserManager()->get(self::UID)) {
			\OC::$server->getUserManager()->createUser(self::UID, self::PWD);
		}
		\OC::$server->getUserSession()->login(self::UID, self::PWD);
		\OC::$server->getSession()->set('user_id', self::UID);
		\OC::$server->getUserFolder(self::UID);
		\OC_Util::setupFS(self::UID);
		
		$this->view = new View('/' . self::UID . '/files');
		$this->view->file_put_contents('file1', self::CONTENT);
	}
	
	public function testRead() {
		$item = new Item($this->l10n, $this->view, '/file1');
		$this->assertTrue($item->isValid());
		
		$chunk = $item->fread();
		$this->assertEquals(self::CONTENT, $chunk);
	}

	public static function tearDownAfterClass() {
		parent::tearDownAfterClass();
		\OC_Util::tearDownFS();
		\OC::$server->getUserManager()->get(self::UID)->delete();
		\OC_User::clearBackends();
	}
}
