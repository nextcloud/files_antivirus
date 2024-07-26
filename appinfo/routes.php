<?php

/**
 * SPDX-FileCopyrightText: 2018-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2014-2015 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
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
