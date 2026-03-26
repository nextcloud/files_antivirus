<!--
 - SPDX-License-Identifier: AGPL-3.0-or-later
 - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
-->

<script setup lang="ts">
import type { Rule } from '../services/antivirusService.ts'

import { t } from '@nextcloud/l10n'
import { computed, ref, watch } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcTextField from '@nextcloud/vue/components/NcTextField'
import NcSelectNative from './NcSelectNative.vue'
import { Statuses, StatusTypes } from '../services/status.ts'

const rule = defineModel<Rule>({ required: true })

const emit = defineEmits<{
	close: []
}>()

const internalRule = ref<Rule>({ ...rule.value })
watch(rule, (newRule) => {
	if (newRule) {
		internalRule.value = { ...newRule }
	}
})

const isNewRule = computed(() => !internalRule.value.id)

/**
 * Handle submitting the form
 */
function onSubmit() {
	rule.value = { ...internalRule.value }
	emit('close')
}
</script>

<template>
	<NcDialog
		isForm
		:name="t('files_antivirus', 'Edit rule')"
		@submit="onSubmit"
		@update:open="$event || $emit('close')">
		<div :class="$style.formBox">
			<NcSelectNative
				v-model="internalRule.status_type"
				:label="t('files_antivirus', 'Match by')"
				:options="StatusTypes" />
			<NcSelectNative
				v-model="internalRule.status"
				:label="t('files_antivirus', 'Mark as')"
				:options="Statuses" />
		</div>

		<div :class="$style.formBox">
			<NcTextField
				v-if="internalRule.status_type === 1"
				v-model="internalRule.result"
				:label="t('files_antivirus', 'Scanner exit status')" />

			<NcTextField
				v-else
				v-model="internalRule.match"
				:label="t('files_antivirus', 'Signature to search')" />

			<NcTextField
				v-model="internalRule.description"
				:label="t('files_antivirus', 'Description')" />
		</div>

		<template #actions>
			<NcButton variant="primary" type="submit">
				{{ isNewRule ? t('files_antivirus', 'Create') : t('files_antivirus', 'Save') }}
			</NcButton>
		</template>
	</NcDialog>
</template>

<style module>
.formBox {
	display: flex;
	flex-direction: column;
	gap: calc(1.5 * var(--default-grid-baseline));
}

.formBox + .formBox {
	margin-top: calc(4 * var(--default-grid-baseline));
}
</style>
