<?php
/**
 * Copyright (c) 2015 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus;

use \OCA\Files_Antivirus\AppInfo\Application;

$app = new Application();
$container = $app->getContainer();
$response = $container->query('\OCA\Files_Antivirus\Controller\SettingsController')->index();
return $response->render();
