<?php

global $RUNTIME_NOAPPS;
$RUNTIME_NOAPPS = true;

if (!defined('PHPUNIT_RUN')) {
	define('PHPUNIT_RUN', 1);
}

require_once __DIR__.'/../../../lib/base.php';

if(!class_exists('PHPUnit_Framework_TestCase') && !class_exists('\PHPUnit\Framework\TestCase')) {
	require_once('PHPUnit/Autoload.php');
}

\OC::$composerAutoloader->addPsr4('Test\\', OC::$SERVERROOT . '/tests/lib/', true);
\OC::$composerAutoloader->addPsr4('Tests\\', OC::$SERVERROOT . '/tests/', true);

\OC_Hook::clear();
\OC_App::loadApp('files_antivirus');
