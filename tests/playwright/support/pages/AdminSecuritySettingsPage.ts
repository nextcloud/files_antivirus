/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Locator, Page } from '@playwright/test'

import { expect } from '@playwright/test'
import { AdvancedSettingsSection } from '../sections/AdvancedSettingsSection.ts'
import { SettingsFormSection } from '../sections/SettingsFormSection.ts'

export class AdminSecuritySettingsPage {
	public readonly url = '/settings/admin/security'
	public readonly root: Locator
	public readonly sectionTitle: Locator
	public readonly settingsForm: SettingsFormSection
	public readonly advancedSettings: AdvancedSettingsSection

	constructor(public readonly page: Page) {
		this.root = page.locator('#antivirus-app')
		this.sectionTitle = page.getByRole('heading', { name: /Antivirus for Files/i })
		this.settingsForm = new SettingsFormSection(this.root)
		this.advancedSettings = new AdvancedSettingsSection(page)
	}

	public async open(): Promise<void> {
		await this.page.goto(this.url)
		await expect(this.root).toBeVisible()
		await expect(this.sectionTitle).toBeVisible()
	}
}
