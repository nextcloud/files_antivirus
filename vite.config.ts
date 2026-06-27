/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { createAppConfig } from '@nextcloud/vite-config'
import { resolve } from 'node:path'
import { defineConfig } from 'vitest/config'

// replaced by vite
declare const __dirname: string

export default createAppConfig({
	adminSettings: resolve(__dirname, 'src', 'adminSettings.ts'),
}, {
	extractLicenseInformation: {
		includeSourceMaps: true,
	},
	config: defineConfig({
		test: {
			environment: 'jsdom',
			include: ['src/**/*.{test,spec}.ts'],
		},
	}),
})
