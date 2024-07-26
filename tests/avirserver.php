<?php

/**
 * SPDX-FileCopyrightText: 2018 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2016 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests;

include __DIR__ . '/DummyClam.php';

set_time_limit(0);
$socketPath = 'tcp://0.0.0.0:5555';
$clam = new DummyClam($socketPath);
$clam->startServer();
