<?php

$app = new \OCA\Files_Antivirus\AppInfo\Application();
$ruleMapper = $app->getContainer()->query('RuleMapper');
$rules = $ruleMapper->findAll();
if(!count($rules)) {
	$ruleMapper->populate();
}

\OC::$server->getConfig()->setAppValue('files_antivirus', 'av_path', '/usr/bin/clamscan');
\OC::$server->getJobList()->add('OCA\Files_Antivirus\Cron\Task');
