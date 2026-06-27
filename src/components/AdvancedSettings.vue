<!--
 - SPDX-License-Identifier: AGPL-3.0-or-later
 - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
-->

<script setup lang="ts">
import { showError, showSuccess } from '@nextcloud/dialogs'
import { getCanonicalLocale, t } from '@nextcloud/l10n'
import { onBeforeMount, reactive, ref } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import AdvancedSettingsDialog from './AdvancedSettingsDialog.vue'
import AdvancedSettingsTable from './AdvancedSettingsTable.vue'
import antivirusService, { type Rule } from '../services/antivirusService.ts'
import { logger } from '../services/logger.ts'

const rules = ref<(Rule & { dirty?: boolean })[]>([])
const editingRule = ref<Rule>()

const loadingState = reactive({
	resetToDefault: false,
	clearAll: false,
})

// Load rules on mount
onBeforeMount(() => loadRules())

/**
 * Handle loading all rules from the API.
 */
async function loadRules() {
	try {
		const response = await antivirusService.listAllRules()
		if (response && response.statuses) {
			rules.value = response.statuses
				.sort((a, b) => String(a.id).localeCompare(String(b.id), getCanonicalLocale(), { numeric: true }))
		}
	} catch (error) {
		showError(t('files_antivirus', 'Failed to load rules'))
		logger.error('Failed to load antivirus rules', { error })
	}
}

/**
 * Handle adding a new rule by opening the dialog with an empty rule.
 */
function onAddRule() {
	editingRule.value = {
		id: '',
		status: 0,
		status_type: 1,
		description: '',
	}
}

/**
 * Handle saving a rule by calling the API and updating the list.
 *
 * @param rule - The rule to save
 */
async function onSaveRule(rule: Rule) {
	try {
		const savedRule = await antivirusService.saveRule(rule)
		showSuccess(t('files_antivirus', 'Rule saved'))
		editingRule.value = undefined
		rules.value = [
			...rules.value.filter((r) => r.id !== savedRule.id),
			savedRule,
		].sort((a, b) => String(a.id).localeCompare(String(b.id), getCanonicalLocale(), { numeric: true }))
		await loadRules()
	} catch (error) {
		showError(t('files_antivirus', 'Failed to save rule'))
		logger.error('Failed to save antivirus rule', { error })
	}
}

/**
 * Delete a rule via the API and remove it from the list.
 *
 * @param rule - The rule to delete
 */
async function deleteRule(rule: Rule) {
	try {
		await antivirusService.deleteRule(rule.id)
		rules.value = rules.value.filter((r) => r.id !== rule.id)
		showSuccess(t('files_antivirus', 'Rule deleted'))
	} catch (error) {
		showError(t('files_antivirus', 'Failed to delete rule'))
		logger.error('Failed to delete antivirus rule', { error })
	}
}

/**
 * Clear all rules via the API and update the list.
 */
async function onClearAll() {
	try {
		loadingState.clearAll = true
		await antivirusService.clearRules()
		rules.value = []
		showSuccess(t('files_antivirus', 'All rules cleared'))
	} catch (error) {
		showError(t('files_antivirus', 'Failed to clear rules'))
		logger.error('Failed to clear antivirus rules', { error })
	} finally {
		loadingState.clearAll = false
	}
}

/**
 * Reset rules to defaults via the API and reload the list.
 */
async function onResetRules() {
	try {
		loadingState.resetToDefault = true
		await antivirusService.resetRules()
		await loadRules()
		showSuccess(t('files_antivirus', 'Rules reset to defaults'))
	} catch (error) {
		showError(t('files_antivirus', 'Failed to reset rules'))
		logger.error('Failed to reset antivirus rules', { error })
	} finally {
		loadingState.resetToDefault = false
	}
}
</script>

<template>
	<div class="antivirus-rules">
		<h3>{{ t('files_antivirus', 'Advanced settings') }}: {{ t('files_antivirus', 'Rules') }}</h3>
		<div :class="$style.advancedSettings__actions">
			<NcButton :disabled="loadingState.clearAll" @click="onClearAll">
				<template v-if="loadingState.clearAll" #icon>
					<NcLoadingIcon />
				</template>
				{{ t('files_antivirus', 'Clear all') }}
			</NcButton>
			<NcButton :disabled="loadingState.resetToDefault" @click="onResetRules">
				<template v-if="loadingState.resetToDefault" #icon>
					<NcLoadingIcon />
				</template>
				{{ t('files_antivirus', 'Reset to defaults') }}
			</NcButton>
			<NcButton variant="primary" @click="onAddRule">
				{{ t('files_antivirus', 'Add a rule') }}
			</NcButton>
		</div>
		<AdvancedSettingsTable
			:rules
			@delete="deleteRule"
			@edit="editingRule = $event" />

		<AdvancedSettingsDialog
			v-if="!!editingRule"
			v-model="editingRule"
			@update:modelValue="onSaveRule"
			@update:open="$event || (editingRule = undefined)" />
	</div>
</template>

<style module>
.advancedSettings__actions {
	display: flex;
	gap: var(--default-grid-baseline);
	justify-content: end;
	margin-bottom: 12px;
}
</style>
