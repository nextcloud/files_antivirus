/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Locator, Page } from '@playwright/test'

export class AdvancedSettingsDialogSection {
	public readonly dialog: Locator
	public readonly matchBySelect: Locator
	public readonly markAsSelect: Locator
	public readonly buttonSubmit: Locator

	constructor(page: Page) {
		this.dialog = page.getByRole('dialog', { name: /Edit rule/i })
		this.matchBySelect = page.getByRole('combobox', { name: 'Match by' })
		this.markAsSelect = page.getByRole('combobox', { name: 'Mark as' })
		this.buttonSubmit = this.dialog.getByRole('button', { name: /Create|Save/i })
	}

	public getField(label: string | RegExp): Locator {
		return this.dialog.getByLabel(label)
	}
}
