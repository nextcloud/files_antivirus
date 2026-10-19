<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\AuditLog;

/**
 * Operations Antivirus for files writes to the admin audit log, in the form `app.entity.action`
 *
 * The values are matched by log consumers (filters, alert rules, SIEM imports),
 * so changing one is a breaking change for them. Case names may be renamed.
 */
enum Operation: string {
	case SettingsUpdated = 'files_antivirus.settings.updated';
	case RuleCreated = 'files_antivirus.rule.created';
	case RuleUpdated = 'files_antivirus.rule.updated';
	case RuleDeleted = 'files_antivirus.rule.deleted';
	case RulesCleared = 'files_antivirus.rules.cleared';
	case RulesReset = 'files_antivirus.rules.reset';

	/**
	 * Short description of when the operation is logged, used for the documentation
	 */
	public function description(): string {
		return match ($this) {
			self::SettingsUpdated => 'The scanner settings were changed in the admin settings',
			self::RuleCreated => 'A rule deciding how a scanner result is classified was added',
			self::RuleUpdated => 'A rule deciding how a scanner result is classified was changed',
			self::RuleDeleted => 'A rule deciding how a scanner result is classified was deleted',
			self::RulesCleared => 'All rules deciding how scanner results are classified were deleted',
			self::RulesReset => 'The rules deciding how scanner results are classified were reset to the defaults',
		};
	}
}
