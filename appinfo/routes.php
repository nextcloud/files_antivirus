<?php
/**
 * Copyright (c) 2014, Lukas Reschke <lukas@owncloud.com>
 * This file is licensed under the Affero General Public License version 3 or later.
 * See the COPYING-README file.
 */

return [
	'routes' => [
		['name' => 'rule#listAll', 'url' => '/settings/rule/listall', 'verb' => 'GET'],
		['name' => 'rule#clear', 'url' => '/settings/rule/clear', 'verb' => 'POST'],
		['name' => 'rule#reset', 'url' => '/settings/rule/reset', 'verb' => 'POST'],
		['name' => 'rule#save', 'url' => '/settings/rule/save', 'verb' => 'POST'],
		['name' => 'rule#delete', 'url' => '/settings/rule/delete', 'verb' => 'POST'],
		['name' => 'settings#save', 'url' => '/settings/save', 'verb' => 'POST'],
	]
];
