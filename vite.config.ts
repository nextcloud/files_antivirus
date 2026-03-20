/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { createAppConfig } from '@nextcloud/vite-config'
import { join } from 'path'

// replaced by vite
declare const __dirname: string

export default createAppConfig({
	adminSettings: join(__dirname, 'src', 'adminSettings.ts'),
}, {
	extractLicenseInformation: {
		includeSourceMaps: true,
	},
})
