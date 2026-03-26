/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { expect, it, vi } from 'vitest'
import { logger } from './logger.ts'

it('builds a configured app logger', () => {
	const spy = vi.spyOn(console, 'error').mockImplementation(() => {})

	logger.error('Test error message')
	expect(spy).toHaveBeenCalledTimes(1)

	// all we need to test is that the app name is included in the log output, the rest is handled by the underlying logger implementation
	expect(spy.mock.calls[0][0]).toContain('files_antivirus')
	expect(spy.mock.calls[0][0]).toContain('Test error message')
})
