<?php

namespace OCA\Files_antivirus\Tests;

include __DIR__ . '/DummyClam.php';

set_time_limit(0);
$socketPath = 'tcp://0.0.0.0:5555';
$clam = new DummyClam($socketPath);
$clam->startServer();
