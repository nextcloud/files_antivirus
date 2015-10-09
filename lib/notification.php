<?php
/**
 * Copyright (c) 2014 Victor Dubiniuk <victor.dubiniuk@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCA\Files_Antivirus;

class Notification {
	public static function sendMail($path){
		if (!\OCP\User::isLoggedIn()){
			return;
		}
		$email = \OCP\Config::getUserValue(\OCP\User::getUser(), 'settings', 'email', '');
		if (\OCP\App::isEnabled(user_ldap)){
                        $user  = \OCP\Config::getUserValue(\OCP\User::getUser(), 'user_ldap', 'displayName', '');
                        if (empty($user)) {
                                $user = \OCP\User::getUser();
                        }
                }
                else {
                        $user = \OCP\User::getUser();
                };
		\OCP\Util::writeLog('files_antivirus', 'Email: '.$email, \OCP\Util::DEBUG);
		if (!empty($email)) {
			$defaults = new \OCP\Defaults();
			$tmpl = new \OCP\Template('files_antivirus', 'notification');
			$tmpl->assign('file', $path);
			$tmpl->assign('host', \OCP\Util::getServerHost());
			$tmpl->assign('user', \OCP\User::getDisplayName());
			$msg = $tmpl->fetchPage();
			$from = \OCP\Util::getDefaultEmailAddress('security-noreply');
			\OCP\Util::sendMail(
					$email,
					$user,
					\OCP\Util::getL10N('files_antivirus')->t('Malware detected'),
					$msg,
					$from,
					$defaults->getName(),
					true
			);
		}
	}
}
