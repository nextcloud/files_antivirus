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
		$config = \OC::$server->getConfig();
		$user = \OC::$server->getUserSession()->getUser();
		$email = $user->getEMailAddress();
		$displayName = $user->getDisplayName();
		if ( strval($displayName) ==='' ) {
			$displayName = $user->getUID();
		}
		\OCP\Util::writeLog('files_antivirus', 'Email: '.$email, \OCP\Util::DEBUG);
		if (!empty($email)) {
			try {
				$tmpl = new \OCP\Template('files_antivirus', 'notification');
				$tmpl->assign('file', $path);
				$tmpl->assign('host', \OC::$server->getRequest()->getServerHost());
				$tmpl->assign('user', $displayName);
				$msg = $tmpl->fetchPage();
				$from = \OCP\Util::getDefaultEmailAddress('security-noreply');
				$mailer = \OC::$server->getMailer();
				$message = $mailer->createMessage();
				$message->setSubject(\OCP\Util::getL10N('files_antivirus')->t('Malware detected'));
				$message->setFrom([$from => 'ownCloud Notifier']);
				$message->setTo([$email => $displayName]);
				$message->setPlainBody($msg);
				$message->setHtmlBody($msg);
				$mailer->send($message);
			} catch (\Exception $e){
				\OC::$server->getLogger()->error( __METHOD__ . ', exception: ' . $e->getMessage(), ['app' => 'files_antivirus']);
			}
		}
	}
}
