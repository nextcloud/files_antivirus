<?php

$installedVersion = \OC::$server->getConfig()->getAppValue('files_antivirus', 'installed_version');
if (version_compare($installedVersion, '0.6', '<')) {
	$query = OCP\DB::prepare( 'SELECT COUNT(*) AS `count`, `fileid` FROM `*PREFIX*files_antivirus` GROUP BY `fileid` HAVING COUNT(*) > 1' );
	$result = $query->execute();
	while( $row = $result->fetchRow()) {
		$deleteQuery = OCP\DB::prepare('DELETE FROM `*PREFIX*files_antivirus` WHERE `fileid` = ?', $row['count']-1);
		$deleteQuery->execute(array($row['fileid']));
	}
}
if (version_compare($installedVersion, '0.6.1', '<') && version_compare($installedVersion, '0.5', '>=')) {
	$alterQuery = OCP\DB::prepare( 'ALTER TABLE `*PREFIX*files_antivirus_status` RENAME TO `*PREFIX*files_avir_status`' );
	$alterQuery->execute();
}
