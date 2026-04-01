/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: 2024 Nextcloud GmbH and Nextcloud contributors
 */

import { getLoggerBuilder } from '@nextcloud/logger'

export const logger = getLoggerBuilder()
	.setApp('files_antivirus')
	.detectLogLevel()
	.build()
