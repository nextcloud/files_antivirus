<!--
 - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 - SPDX-License-Identifier: AGPL-3.0-or-later
 -->

<script setup lang="ts">
import type { Settings } from '../services/antivirusService.ts'

import { loadState } from '@nextcloud/initial-state'
import { t } from '@nextcloud/l10n'
import { ref } from 'vue'
import NcSettingsSection from '@nextcloud/vue/components/NcSettingsSection'
import AdvancedSettings from '../components/AdvancedSettings.vue'
import SettingsForm from '../components/SettingsForm.vue'

const docUrl = loadState<string>('files_antivirus', 'docUrl')

const config = ref(loadState<Settings>('files_antivirus', 'config'))
const showAdvancedSettings = ref(false)
</script>

<template>
	<NcSettingsSection
		:name="t('files_antivirus', 'Antivirus for Files')"
		:docUrl>
		<SettingsForm
			v-model="config"
			v-model:advancedSettings="showAdvancedSettings" />
		<AdvancedSettings v-if="showAdvancedSettings" />
	</NcSettingsSection>
</template>
