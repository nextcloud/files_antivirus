/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { runOcc } from '@nextcloud/e2e-test-server'
import { expect, mergeTests } from '@playwright/test'
import { test as adminSettingsTest } from '../support/fixtures/admin-settings.ts'
import { test as adminUserTest } from '../support/fixtures/admin-user.ts'

const test = mergeTests(adminUserTest, adminSettingsTest)

test.beforeEach(async ({ adminSettings }) => {
	// Reset to some state in backend
	await runOcc(['config:app:set', 'files_antivirus', 'av_mode', '--value=kaspersky'])
	await adminSettings.open()
})

test('Can see advanced settings', async ({ adminSettings }) => {
	const form = adminSettings.settingsForm
	// not visible for Kaspersky
	await expect(form.buttonAdvancedSettings).not.toBeVisible()
	// but visible for ClamAV Executable
	await form.setMode('ClamAV Executable')
	await expect(form.buttonAdvancedSettings).toBeVisible()

	// see the table
	await form.buttonAdvancedSettings.click()
	await expect(adminSettings.advancedSettings.table).toBeVisible()
	// and hide the table again
	await form.buttonAdvancedSettings.click()
	await expect(adminSettings.advancedSettings.table).not.toBeVisible()
})

test('General admin settings usage', async ({ adminSettings, page }) => {
	const form = adminSettings.settingsForm

	// see that current settings are loaded and save button is disabled
	await expect(form.modeSelect).toHaveValue('kaspersky')
	await expect(form.buttonSave).toHaveText(/Settings saved/i)
	await expect(form.buttonSave).toBeDisabled()
	await expect(form.getField(/Extra command line options/i)).toHaveCount(0) // no extra cmd options for Kaspersky

	// can change the mode to ClamAV Executable and see the relevant fields, fill them and save
	await form.setMode('ClamAV Executable')
	await expect(form.getField(/Path to clamscan/i)).toBeVisible()
	await form.getField(/Path to clamscan/i).fill('/usr/bin/clamscan')
	await form.getField(/Extra command line options/i).fill('--allmatch, --stdout')

	await expect(form.buttonSave).toHaveText('Save')
	await expect(form.buttonSave).not.toBeDisabled()
	await form.buttonSave.click()
	// disabled again
	await expect(form.buttonSave).toHaveText(/Settings saved/i)
	await expect(form.buttonSave).toBeDisabled()

	await page.reload()

	// settings survived reload
	await expect(form.modeSelect).toHaveValue('executable')
	await expect(form.getField(/Extra command line options/i)).toHaveValue('--allmatch, --stdout')
})
