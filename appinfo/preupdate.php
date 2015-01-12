<?php

$installedVersion=OCP\Config::getAppValue('files_antivirus', 'installed_version');
if (version_compare($installedVersion, '0.6', '<')) {
	$query = OC_DB::prepare( 'SELECT COUNT(*) AS `count`, `fileid` FROM `*PREFIX*files_antivirus` GROUP BY `fileid` HAVING COUNT(*) > 1' );
	$result = $query->execute();
	while( $row = $result->fetchRow()) {
		$deleteQuery = OC_DB::prepare('DELETE FROM `*PREFIX*files_antivirus` WHERE `fileid` = ?', $row['count']-1);
		$deleteQuery->execute(array($row['fileid']));
	}
}
if (version_compare($installedVersion, '0.6.1', '<')) {
	$alterQuery = OC_DB::prepare( 'ALTER TABLE `*PREFIX*files_antivirus_status` RENAME TO `*PREFIX*files_avir_status`' );
	$alterQuery->execute();
}