<?php
/**
 * Copyright (c) 2014, Lukas Reschke <lukas@owncloud.com>
 * This file is licensed under the Affero General Public License version 3 or later.
 * See the COPYING-README file.
 */

$application = new \OCA\Files_Antivirus\AppInfo\Application();
$application->registerRoutes($this, array(
	'routes' => array(
		array('name' => 'rule#listAll', 'url' => 'settings/rule/listall', 'verb' => 'GET'),
		array('name' => 'rule#clear', 'url' => 'settings/rule/clear', 'verb' => 'POST'),
		array('name' => 'rule#reset', 'url' => 'settings/rule/reset', 'verb' => 'POST'),
		array('name' => 'rule#save', 'url' => 'settings/rule/save', 'verb' => 'POST'),
		array('name' => 'rule#delete', 'url' => 'settings/rule/delete', 'verb' => 'POST'),
		array('name' => 'settings#save', 'url' => 'settings/save', 'verb' => 'POST'),
	)
));
