<!--
 - SPDX-License-Identifier: AGPL-3.0-or-later
 - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
-->

<script setup lang="ts">
import { showError, showSuccess } from '@nextcloud/dialogs'
import { t } from '@nextcloud/l10n'
import { computed, ref, toRaw, watch } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcFormBox from '@nextcloud/vue/components/NcFormBox'
import NcFormGroup from '@nextcloud/vue/components/NcFormGroup'
import NcInputField from '@nextcloud/vue/components/NcInputField'
import NcSelectNative from './NcSelectNative.vue'
import antivirusService, { type Settings } from '../services/antivirusService.ts'
import { logger } from '../services/logger.ts'

const settings = defineModel<Settings>({ required: true })
const showAdvancedSettings = defineModel<boolean>('advancedSettings', { default: false })
const cmdOptions = computed({
	get() {
		return settings.value.avCmdOptions.join(', ')
	},
	set(newValue: string) {
		settings.value.avCmdOptions = newValue.split(',').map((option) => option.trim())
	},
})

const modeOptions = [
	{ value: 'executable', label: t('files_antivirus', 'ClamAV Executable') },
	{ value: 'daemon', label: t('files_antivirus', 'ClamAV Daemon') },
	{ value: 'socket', label: t('files_antivirus', 'ClamAV Socket') },
	{ value: 'kaspersky', label: 'Kaspersky' },
	{ value: 'icap', label: 'ICAP' },
]

const infectedActionOptions = [
	{ value: 'only_log', label: t('files_antivirus', 'Only log') },
	{ value: 'delete', label: t('files_antivirus', 'Delete file') },
]

const icapModeOptions = [
	{ value: 'reqmod', label: 'REQMOD' },
	{ value: 'respmod', label: 'RESPMOD' },
]

const icapPresetOptions = [
	{ value: 'clamav', label: 'ClamAV / c-icap' },
	{ value: 'kaspersky', label: 'Kaspersky' },
	{ value: 'fortisandbox', label: 'FortiSandbox' },
]

const icapPresets = {
	clamav: {
		service: 'avscan',
		header: 'X-Infection-Found',
		mode: 'reqmod',
	},
	kaspersky: {
		service: 'req',
		header: 'X-Virus-ID',
		mode: 'reqmod',
	},
	fortisandbox: {
		service: 'respmod',
		header: 'X-Infection-Found',
		mode: 'respmod',
	},
}

const selectedIcapPreset = ref('')
watch(selectedIcapPreset, (newPreset) => {
	settings.value.avIcapMode = icapPresets[newPreset].mode
	settings.value.avIcapRequestService = icapPresets[newPreset].service
	settings.value.avIcapResponseHeader = icapPresets[newPreset].header
})

watch(() => settings.value.avMode, (newMode: string) => {
	if (newMode === 'kaspersky' || newMode === 'icap') {
		showAdvancedSettings.value = false
	}
})

const saveStatus = ref<'saving' | 'saved' | 'changes'>('saved')
watch(settings, () => {
	if (saveStatus.value !== 'saving') {
		saveStatus.value = 'changes'
	}
}, { deep: true })

/**
 * Handle form submission to save settings.
 */
async function onSave() {
	if (saveStatus.value !== 'changes') {
		return
	}
	try {
		saveStatus.value = 'saving'
		await antivirusService.saveSettings(toRaw(settings.value))
		saveStatus.value = 'saved'
		showSuccess(t('files_antivirus', 'Settings saved successfully'))
	} catch (error) {
		saveStatus.value = 'changes'
		showError(t('files_antivirus', 'Failed to save settings'))
		logger.error('Failed to save antivirus settings', { error })
	}
}
</script>

<template>
	<form @submit.prevent="onSave">
		<NcSelectNative
			v-model="settings.avMode"
			:label="t('files_antivirus', 'Mode')"
			:options="modeOptions" />

		<NcFormBox v-if="settings.avMode === 'executable'">
			<NcInputField
				v-model="settings.avPath"
				:label="t('files_antivirus', 'Path to clamscan')"
				required />

			<NcInputField
				v-model="cmdOptions"
				:label="t('files_antivirus', 'Extra command line options')"
				:helperText="t('files_antivirus', 'Extra command line options (comma-separated)')" />
		</NcFormBox>

		<NcInputField
			v-else-if="settings.avMode === 'socket'"
			v-model="settings.avSocket"
			:label="t('files_antivirus', 'Socket')"
			:helperText="t('files_antivirus', 'ClamAV Socket.')"
			required />

		<NcFormBox v-else>
			<NcInputField
				v-model="settings.avHost"
				:label="t('files_antivirus', 'Host')"
				:helperText="t('files_antivirus', 'Address of Antivirus Host.')"
				required />
			<NcInputField
				v-model="settings.avPort"
				:label="t('files_antivirus', 'Port')"
				:helperText="t('files_antivirus', 'Port number of Antivirus Host.')"
				type="number"
				min="1"
				max="65535"
				required />
		</NcFormBox>

		<NcFormGroup v-if="settings.avMode === 'icap'" label="ICAP">
			<NcSelectNative
				v-model="selectedIcapPreset"
				:label="t('files_antivirus', 'ICAP preset')"
				:options="icapPresetOptions"
				:placeholder="t('files_antivirus', 'Select')" />

			<NcSelectNative
				v-model="selectedIcapPreset"
				:label="t('files_antivirus', 'ICAP mode')"
				:options="icapModeOptions" />

			<NcInputField
				v-model="settings.avIcapRequestService"
				:label="t('files_antivirus', 'ICAP service')"
				required />

			<NcInputField
				v-model="settings.avIcapResponseHeader"
				:label="t('files_antivirus', 'ICAP virus response header')" />

			<NcCheckboxRadioSwitch
				v-model="settings.avIcapTls"
				type="switch">
				{{ t('files_antivirus', 'Use TLS encryption.') }}
			</NcCheckboxRadioSwitch>
		</NcFormGroup>

		<NcFormGroup :label="t('files_antivirus', 'Streaming options')">
			<NcInputField
				v-model="settings.avMaxFileSize"
				:label="t('files_antivirus', 'File size limit')"
				:helperText="t('files_antivirus', 'File size limit for periodic background scans and chunked uploads in bytes, -1 means no limit')"
				type="number"
				min="-1" />

			<NcInputField
				v-model="settings.avScanFirstBytes"
				:label="t('files_antivirus', 'First bytes to scan')"
				:helperText="t('files_antivirus', 'Check only first bytes of the file, -1 means no limit')"
				type="number"
				min="-1" />

			<NcInputField
				v-model="settings.avStreamMaxLength"
				:label="t('files_antivirus', 'Maximum stream length')"
				:helperText="t('files_antivirus', 'Reopen socket after this number of bytes.')"
				type="number"
				min="1024" />
		</NcFormGroup>

		<NcFormGroup :label="t('files_antivirus', 'Infected file handling')">
			<NcSelectNative
				v-model="settings.avInfectedAction"
				:label="t('files_antivirus', 'When infected files are found during a background scan')"
				:options="infectedActionOptions"
				:placeholder="t('files_antivirus', 'Select')" />

			<NcCheckboxRadioSwitch
				v-model="settings.avBlockUnreachable"
				type="switch">
				{{ t('files_antivirus', 'Block uploads when scanner is not reachable') }}
			</NcCheckboxRadioSwitch>

			<NcCheckboxRadioSwitch
				v-model="settings.avBlockUnscannable"
				type="switch">
				{{ t('files_antivirus', 'Block unscannable files (such as encrypted archives)') }}
			</NcCheckboxRadioSwitch>
		</NcFormGroup>

		<div :class="$style.settingsForm__actions">
			<NcButton
				v-if="settings.avMode !== 'kaspersky' && settings.avMode !== 'icap'"
				v-model:pressed="showAdvancedSettings"
				variant="tertiary">
				{{ t('files_antivirus', 'Advanced settings') }}
			</NcButton>

			<NcButton
				type="submit"
				:disabled="saveStatus !== 'changes'"
				:variant="saveStatus === 'changes' ? 'primary' : 'tertiary'">
				{{ saveStatus === 'changes'
					? t('files_antivirus', 'Save')
					: (saveStatus === 'saved' ? t('files_antivirus', 'Settings saved') : t('files_antivirus', 'Saving …'))
				}}
			</NcButton>
		</div>
	</form>
</template>

<style module>
.settingsForm__actions {
	display: flex;
	gap: calc(3 * var(--default-grid-baseline));
	justify-content: end;
	width: 100%;
}
</style>
