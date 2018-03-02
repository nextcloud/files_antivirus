<?php

$app = new \OCA\Files_Antivirus\AppInfo\Application();
$ruleMapper = $app->getContainer()->query(\OCA\Files_Antivirus\Db\RuleMapper::class);
$rules = $ruleMapper->findAll();
if(!count($rules)) {
	$ruleMapper->populate();
}

\OC::$server->getConfig()->setAppValue('files_antivirus', 'av_path', '/usr/bin/clamscan');
