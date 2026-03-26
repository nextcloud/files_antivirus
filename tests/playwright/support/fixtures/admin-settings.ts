/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { test as baseTest } from '@playwright/test'
import { AdminSecuritySettingsPage } from '../pages/AdminSecuritySettingsPage.ts'

interface AdminSettingsFixture {
	adminSettings: AdminSecuritySettingsPage
}

export const test = baseTest.extend<AdminSettingsFixture>({
	adminSettings: async ({ page }, use) => {
		await use(new AdminSecuritySettingsPage(page))
	},
})
