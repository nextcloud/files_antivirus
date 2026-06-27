/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Rule } from './antivirusService.ts'

import { http, HttpResponse } from 'msw'
import { setupServer } from 'msw/node'
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import antivirusService from './antivirusService.ts'

vi.mock('@nextcloud/router', () => ({
	generateUrl: vi.fn(() => 'http://localhost/apps/files_antivirus'),
}))

const server = setupServer()

beforeAll(() => server.listen())
afterEach(() => {
	server.resetHandlers()
	vi.restoreAllMocks()
})
afterAll(() => server.close())

describe('antivirusService', () => {
	it('lists all rules', async () => {
		const statuses: Rule[] = [
			{ id: 1, status_type: 1, description: 'Exit status', status: 0 },
		]

		server.use(http.get('http://localhost/apps/files_antivirus/settings/rule/listall', () => {
			return HttpResponse.json({ statuses })
		}))

		const response = await antivirusService.listAllRules()

		expect(response).toEqual({ statuses })
	})

	it('saves a rule using statusType payload', async () => {
		const rule: Rule = {
			id: 'rule-1',
			status_type: 2,
			description: 'Virus output contains token',
			status: 1,
			result: 'EICAR',
		}

		let requestBody: Record<string, unknown> | null = null

		server.use(http.post('http://localhost/apps/files_antivirus/settings/rule/save', async ({ request }) => {
			requestBody = (await request.json()) as Record<string, unknown>
			return HttpResponse.json(rule)
		}))

		const response = await antivirusService.saveRule(rule)

		expect(response).toEqual(rule)
		expect(requestBody).toMatchObject({
			id: 'rule-1',
			description: 'Virus output contains token',
			status: 1,
			result: 'EICAR',
			statusType: 2,
		})
		expect(requestBody).not.toHaveProperty('status_type')
	})

	it('deletes a rule', async () => {
		let requestBody: Record<string, unknown> | null = null

		server.use(http.post('http://localhost/apps/files_antivirus/settings/rule/delete', async ({ request }) => {
			requestBody = (await request.json()) as Record<string, unknown>
			return HttpResponse.json({ id: 7, deleted: true })
		}))

		const response = await antivirusService.deleteRule(7)

		expect(requestBody).toEqual({ id: 7 })
		expect(response).toEqual({ id: 7, deleted: true })
	})

	it('clears all rules', async () => {
		server.use(http.post('http://localhost/apps/files_antivirus/settings/rule/clear', () => {
			return HttpResponse.json({ success: true })
		}))

		const response = await antivirusService.clearRules()

		expect(response).toEqual({ success: true })
	})

	it('resets all rules', async () => {
		server.use(http.post('http://localhost/apps/files_antivirus/settings/rule/reset', () => {
			return HttpResponse.json({ success: true })
		}))

		const response = await antivirusService.resetRules()

		expect(response).toEqual({ success: true })
	})

	it('saves settings', async () => {
		const payload = {
			avMode: 'daemon',
			avHost: 'clamav.local',
			avPort: 3310,
		}

		let requestBody: Record<string, unknown> | null = null

		server.use(http.post('http://localhost/apps/files_antivirus/settings/save', async ({ request }) => {
			requestBody = (await request.json()) as Record<string, unknown>
			return HttpResponse.json({ saved: true })
		}))

		const response = await antivirusService.saveSettings(payload)

		expect(requestBody).toEqual(payload)
		expect(response).toEqual({ saved: true })
	})
})
