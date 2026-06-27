/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { runOcc } from '@nextcloud/e2e-test-server'
import { expect, mergeTests } from '@playwright/test'
import { test as adminSettingsTest } from '../support/fixtures/admin-settings.ts'
import { test as adminUserTest } from '../support/fixtures/admin-user.ts'
import { AdvancedSettingsDialogSection } from '../support/sections/AdvancedSettingsDialogSection.ts'

const test = mergeTests(adminUserTest, adminSettingsTest)

test.beforeEach(async ({ adminSettings }) => {
	await runOcc(['config:app:set', 'files_antivirus', 'av_mode', '--value=executable'])
	await adminSettings.open()

	const form = adminSettings.settingsForm
	await expect(form.buttonAdvancedSettings).toBeVisible()
	await form.buttonAdvancedSettings.click()
	await expect(adminSettings.advancedSettings.table).toBeVisible()
})

test('Can reset and clear the advanced settings list of rules', async ({ adminSettings, page }) => {
	const form = adminSettings.settingsForm
	const advanced = adminSettings.advancedSettings

	// reset to defaults
	const responsePromise = page.waitForResponse('**/reset')
	await advanced.buttonResetDefaults.click()
	await responsePromise
	await expect(advanced.table.getByRole('row').nth(2)).toBeVisible()

	// can clear the list
	const responsePromise2 = page.waitForResponse('**/clear')
	await expect(advanced.buttonClearAll).toBeVisible()
	await advanced.buttonClearAll.click()
	await responsePromise2
	expect(await advanced.table.getByRole('row').count()).toBe(1) // only header row left
	// see it is persisted after reload
	await page.reload()
	await expect(form.buttonAdvancedSettings).toBeVisible()
	await form.buttonAdvancedSettings.click()
	await expect(advanced.table).toBeVisible()
	expect(await advanced.table.getByRole('row').count()).toBe(1)

	// can reset the list again
	const responsePromise3 = page.waitForResponse('**/reset')
	await advanced.buttonResetDefaults.click()
	await responsePromise3
	await expect(advanced.table.getByRole('row')).not.toHaveCount(1)
	expect(await advanced.table.getByRole('row').count()).toBeGreaterThan(5)

	// see it is persisted after reload
	await page.reload()
	await expect(form.buttonAdvancedSettings).toBeVisible()
	await form.buttonAdvancedSettings.click()
	await expect(advanced.table).toBeVisible()
	await expect(advanced.table.getByRole('row')).not.toHaveCount(1)
	expect(await advanced.table.getByRole('row').count()).toBeGreaterThan(5)
})

test.describe('rule management', () => {
	test.beforeEach(async ({ adminSettings, page }) => {
		const responsePromise = page.waitForResponse('**/clear')
		await adminSettings.advancedSettings.buttonClearAll.click()
		await responsePromise
	})

	test('Can add new rule', async ({ adminSettings, page }) => {
		const advanced = adminSettings.advancedSettings
		const form = adminSettings.settingsForm

		await expect(advanced.buttonAddRule).toBeVisible()
		await advanced.buttonAddRule.click()

		const request = page.waitForRequest('**/save')
		const dialog = new AdvancedSettingsDialogSection(adminSettings.page)
		await expect(dialog.dialog).toBeVisible()
		await dialog.matchBySelect.selectOption('2')
		await dialog.markAsSelect.selectOption('1')
		await dialog.getField(/Signature to search/i).fill('FOUND.VIRUS')
		await dialog.getField(/Description/i).fill('Created by e2e test')
		await dialog.buttonSubmit.click()
		await request

		const row = advanced.table.getByRole('row')
			.filter({ hasText: 'Created by e2e test' })
		await expect(row).toBeVisible()

		await page.reload()
		await form.buttonAdvancedSettings.click()
		await expect(advanced.table).toBeVisible()
		await expect(row).toBeVisible()
	})

	test('Can delete rule', async ({ adminSettings, page }) => {
		const advanced = adminSettings.advancedSettings
		const form = adminSettings.settingsForm

		await expect(advanced.buttonAddRule).toBeVisible()
		await advanced.buttonAddRule.click()

		const request = page.waitForRequest('**/save')
		const dialog = new AdvancedSettingsDialogSection(adminSettings.page)
		await expect(dialog.dialog).toBeVisible()
		await dialog.matchBySelect.selectOption('2')
		await dialog.markAsSelect.selectOption('1')
		await dialog.getField(/Signature to search/i).fill('FOUND.VIRUS')
		await dialog.getField(/Description/i).fill('Created by e2e test')
		await dialog.buttonSubmit.click()
		await request

		const row = advanced.table.getByRole('row')
			.filter({ hasText: 'Created by e2e test' })
		await expect(row).toBeVisible()

		const deleteRequest = page.waitForRequest('**/delete')
		await row.getByRole('button', { name: /Delete/i }).click()
		await deleteRequest

		await expect(row).not.toBeVisible()

		// see it is persisted after reload
		await page.reload()
		await form.buttonAdvancedSettings.click()
		await expect(advanced.table).toBeVisible()
		await expect(row).toHaveCount(0)
	})

	test('Can edit rule', async ({ adminSettings, page }) => {
		const advanced = adminSettings.advancedSettings
		const form = adminSettings.settingsForm

		await expect(advanced.buttonAddRule).toBeVisible()
		await advanced.buttonAddRule.click()

		const request = page.waitForRequest('**/save')
		const dialog = new AdvancedSettingsDialogSection(adminSettings.page)
		await expect(dialog.dialog).toBeVisible()
		await dialog.matchBySelect.selectOption('2')
		await dialog.markAsSelect.selectOption('1')
		await dialog.getField(/Signature to search/i).fill('FOUND.VIRUS')
		await dialog.getField(/Description/i).fill('Created by e2e test')
		await dialog.buttonSubmit.click()
		await request

		const row = advanced.table.getByRole('row')
			.filter({ hasText: 'Created by e2e test' })
		await expect(row).toBeVisible()

		const modificationRequest = page.waitForRequest('**/save')
		await row.getByRole('button', { name: /Edit/i }).click()
		await expect(dialog.dialog).toBeVisible()
		await expect(dialog.getField(/Description/i)).toHaveValue('Created by e2e test')
		await dialog.getField(/Description/i).fill('Modified by e2e test')
		await dialog.buttonSubmit.click()
		await modificationRequest

		await expect(row).not.toBeVisible()
		const newRow = advanced.table.getByRole('row')
			.filter({ hasText: 'Modified by e2e test' })
		await expect(newRow).toBeVisible()

		// see it is persisted after reload
		await page.reload()
		await form.buttonAdvancedSettings.click()
		await expect(advanced.table).toBeVisible()
		await expect(row).toHaveCount(0)
		await expect(newRow).toBeVisible()
	})
})
