/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Locator, Page } from '@playwright/test'

export class AdvancedSettingsSection {
	public readonly root: Locator
	public readonly table: Locator
	public readonly buttonAddRule: Locator
	public readonly buttonClearAll: Locator
	public readonly buttonResetDefaults: Locator

	constructor(page: Page) {
		this.root = page.locator('.antivirus-rules')
		this.table = this.root.locator('table')
		this.buttonAddRule = this.root.getByRole('button', { name: /Add a rule/i })
		this.buttonClearAll = this.root.getByRole('button', { name: /Clear all/i })
		this.buttonResetDefaults = this.root.getByRole('button', { name: /Reset to defaults/i })
	}

	public getRowByRuleId(id: string): Locator {
		return this.table.locator(`tbody tr[data-id="${id}"]`)
	}

	public getEditButtonByRuleId(id: string): Locator {
		return this.getRowByRuleId(id).getByRole('button', { name: /Edit/i })
	}

	public getDeleteButtonByRuleId(id: string): Locator {
		return this.getRowByRuleId(id).getByRole('button', { name: /Delete/i })
	}
}
