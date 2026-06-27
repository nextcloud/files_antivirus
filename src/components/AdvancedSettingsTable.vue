<!--
 - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Rule } from '../services/antivirusService.ts'

import { mdiPencilOutline, mdiTrashCanOutline } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import { Statuses, StatusTypes } from '../services/status.ts'

defineProps<{
	rules: Rule[]
}>()

defineEmits<{
	delete: [rule: Rule]
	edit: [rule: Rule]
}>()
</script>

<template>
	<table :class="$style.advancedSettingsTable">
		<thead>
			<tr>
				<th>{{ t('files_antivirus', 'Match by') }}</th>
				<th :title="t('files_antivirus', 'Scanner exit status or signature to search')">
					{{ t('files_antivirus', 'Scanner exit status or signature to search') }}
				</th>
				<th>{{ t('files_antivirus', 'Description') }}</th>
				<th :class="$style.advancedSettingsTable__rowMarkAs">
					{{ t('files_antivirus', 'Mark as') }}
				</th>
				<th :class="$style.advancedSettingsTable__rowActions">
					<span class="hidden-visually">{{ t('files_antivirus', 'Actions') }}</span>
				</th>
			</tr>
		</thead>
		<tbody>
			<tr v-for="rule in rules" :key="rule.id" :data-id="rule.id">
				<td>
					{{ StatusTypes.find((s) => s.value === rule.status_type)!.label }}
				</td>
				<td>
					{{ rule.status_type === 1 ? rule.result : rule.match }}
				</td>
				<td :title="rule.description">
					{{ rule.description }}
				</td>
				<td>
					{{ Statuses.find((s) => s.value === rule.status)!.label }}
				</td>
				<td>
					<div :class="$style.advancedSettingsTable__rowActionsWrapper">
						<NcButton
							:aria-label="t('files_antivirus', 'Edit')"
							:title="t('files_antivirus', 'Edit')"
							@click="$emit('edit', rule)">
							<template #icon>
								<NcIconSvgWrapper :path="mdiPencilOutline" />
							</template>
						</NcButton>
						<NcButton
							:aria-label="t('files_antivirus', 'Delete')"
							:title="t('files_antivirus', 'Delete')"
							variant="error"
							@click="$emit('delete', rule)">
							<template #icon>
								<NcIconSvgWrapper :path="mdiTrashCanOutline" />
							</template>
						</NcButton>
					</div>
				</td>
			</tr>
		</tbody>
	</table>
</template>

<style module>
.advancedSettingsTable {
	table-layout: fixed;
	width: 100%;

	td, th {
		border-bottom: 1px solid var(--color-border) !important;
		overflow: hidden;
		text-overflow: ellipsis;
		padding-inline: var(--default-grid-baseline);
	}

	th {
		color: var(--color-text-maxcontrast);
		height: var(--default-clickable-area);
	}
}

.advancedSettingsTable__rowMarkAs {
	width: 15%;
}

.advancedSettingsTable__rowActions {
	width: calc(3 * var(--default-grid-baseline) + 2 * var(--default-clickable-area));
}

.advancedSettingsTable__rowActionsWrapper {
	display: flex;
	gap: var(--default-grid-baseline);
}
</style>
