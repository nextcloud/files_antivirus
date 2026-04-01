/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { User } from '@nextcloud/e2e-test-server'
import { test as base } from '@playwright/test'

const admin = new User('admin', 'admin', 'en')

export const test = base.extend({
	page: async ({ browser, baseURL }, use) => {
		const page = await browser.newPage({
			storageState: undefined,
			baseURL,
		})

		await page.goto('/login')
		await page.locator('#user')
			.fill(admin.userId)
		await page.locator('#password')
			.fill(admin.password)
		await page.getByRole('button', { name: 'Log in', exact: true })
			.click()

		await use(page)
		await page.close()
	},
})
