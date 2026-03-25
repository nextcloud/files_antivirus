/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Locator } from '@playwright/test'

export class SettingsFormSection {
	public readonly form: Locator
	public readonly modeSelect: Locator
	public readonly buttonAdvancedSettings: Locator
	public readonly buttonSave: Locator

	constructor(root: Locator) {
		this.form = root.locator('form')
		this.modeSelect = root.getByRole('combobox', { name: 'Mode' })
		this.buttonAdvancedSettings = this.form.getByRole('button', { name: /Advanced settings/i })
		this.buttonSave = this.form.getByRole('button', { name: /Save|Settings saved|Saving/i })
	}

	public async setMode(label: string): Promise<void> {
		await this.modeSelect.selectOption(label)
	}

	public getField(label: string | RegExp): Locator {
		return this.form.getByLabel(label)
	}
}
