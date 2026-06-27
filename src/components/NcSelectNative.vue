<!--
 - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { useId, warn, watch } from 'vue'

type ModelValue = string | number

defineOptions({ inheritAttrs: false })

const modelValue = defineModel<ModelValue>()

const props = withDefaults(defineProps<{
	/**
	 * The label to display for the select field.
	 */
	label?: string | undefined

	/**
	 * Set to true if you use a custom external label.
	 */
	labelOutside?: boolean

	/**
	 * The ID of the select element.
	 * Can be used with `labelOutside` to link the label to the select for better accessibility.
	 */
	id?: string

	/**
	 * The options to display in the select dropdown.
	 */
	options: readonly {
		value: ModelValue
		label: string
	}[]

	/**
	 * The placeholder text to display when no option is selected.
	 */
	placeholder?: string | undefined

	/**
	 * Whether the select field is required. If true, the user must select an option before submitting the form.
	 */
	required?: boolean
}>(), {
	id: () => useId(),
	label: undefined,
	placeholder: undefined,
})

watch([() => props.label, () => props.labelOutside], ([label, labelOutside]) => {
	if (!labelOutside && !label) {
		warn('NcSelectNative: No label provided. Please provide a label for accessibility or set labelOutside to true.')
	}
})
</script>

<template>
	<div :class="$style.selectNative">
		<label
			v-if="!props.labelOutside"
			:class="$style.selectNative__label"
			:for="props.id">
			{{ props.label }}
		</label>
		<select
			:id
			v-model="modelValue"
			:class="$style.selectNative__select"
			:required>
			<option
				v-if="props.placeholder"
				value=""
				disabled
				hidden
				:selected="!!modelValue">
				{{ props.placeholder }}
			</option>
			<option
				v-for="option in options"
				:key="option.value"
				:value="option.value">
				{{ option.label }}
			</option>
		</select>
	</div>
</template>

<style module>
.selectNative {
	position: relative;
	padding-block: 0.5lh 0px;
}

.selectNative__label {
	position: absolute;
	inset-block: 0;
	inset-inline-start: var(--border-radius-element);
	height: 1lh;
	background: var(--color-main-background);
	padding-inline: var(--default-grid-baseline);
}

.selectNative__select {
	margin: unset;
	width: 100%;
}

.selectNative__select:hover,
.selectNative__select:focus {
	background-color: var(--color-main-background) !important;
}
</style>
