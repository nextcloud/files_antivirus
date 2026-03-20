/**
 * SPDX-FileCopyrightText: 2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import axios from '@nextcloud/axios'
import { generateUrl } from '@nextcloud/router'

export interface Rule {
	id: string | number
	status_type: number
	result?: string
	match?: string
	description: string
	status: number
}

export interface Settings {
	avMode: string
	avSocket: string
	avHost: string
	avPort: number
	avIcapTls: boolean
	avIcapMode: string
	avIcapRequestService: string
	avIcapResponseHeader: string
	avStreamMaxLength: number
	avPath: string
	avCmdOptions: string[]
	avMaxFileSize: number
	avScanFirstBytes: number
	avInfectedAction: string
	avBlockUnreachable: boolean
	avBlockUnscannable: boolean
}

export interface ApiResponse {
	id?: string | number
	[key: string]: unknown
}

class AntivirusService {
	private baseUrl = generateUrl('/apps/files_antivirus')

	async listAllRules(): Promise<{ statuses: Rule[] }> {
		const response = await axios.get<{ statuses: Rule[] }>(`${this.baseUrl}/settings/rule/listall`)
		return response.data
	}

	async saveRule(rule: Rule): Promise<Rule> {
		const requestBody = { statusType: rule.status_type, ...rule, status_type: undefined }
		const { data } = await axios.post<Rule>(
			`${this.baseUrl}/settings/rule/save`,
			requestBody,
		)
		return data
	}

	async deleteRule(id: string | number): Promise<ApiResponse> {
		const response = await axios.post<ApiResponse>(
			`${this.baseUrl}/settings/rule/delete`,
			{ id },
		)
		return response.data
	}

	async clearRules(): Promise<ApiResponse> {
		const response = await axios.post<ApiResponse>(`${this.baseUrl}/settings/rule/clear`)
		return response.data
	}

	async resetRules(): Promise<ApiResponse> {
		const response = await axios.post<ApiResponse>(`${this.baseUrl}/settings/rule/reset`)
		return response.data
	}

	async saveSettings(data: Partial<Settings>): Promise<ApiResponse> {
		const response = await axios.post<ApiResponse>(
			`${this.baseUrl}/settings/save`,
			data,
		)
		return response.data
	}
}

export default new AntivirusService()
