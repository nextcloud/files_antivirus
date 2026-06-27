/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: 2024 Nextcloud GmbH and Nextcloud contributors
 */

import { t } from '@nextcloud/l10n'

export const Statuses = Object.freeze([
	{ value: 0, label: t('files_antivirus', 'Clean') },
	{ value: 1, label: t('files_antivirus', 'Infected') },
	{ value: -1, label: t('files_antivirus', 'Unchecked') },
] as const)

export const StatusTypes = Object.freeze([
	{ value: 1, label: t('files_antivirus', 'Scanner exit status') },
	{ value: 2, label: t('files_antivirus', 'Scanner output') },
] as const)
