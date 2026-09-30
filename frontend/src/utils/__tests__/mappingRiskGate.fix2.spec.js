import { expect, it } from 'vitest'
import { ackWarningCodes, confirmWarnings } from '../mappingRiskGate'

it('reads source warnings from the actual meta.warnings envelope', () => {
  const error = { response: { status: 422, data: { code: 'MAPPING_ACK_REQUIRED', meta: { warnings: [{ code: 'MAPPING_SOURCE_ATTR_UNSET' }] } } } }
  expect(ackWarningCodes(error)).toEqual(['MAPPING_SOURCE_ATTR_UNSET'])
})

it('keeps legacy top-level warning responses readable', () => {
  const error = { response: { status: 422, data: { code: 'MAPPING_ACK_REQUIRED', warnings: [{ code: 'MAPPING_TARGETS_ADMIN_ROLE' }] } } }
  expect(ackWarningCodes(error)).toEqual(['MAPPING_TARGETS_ADMIN_ROLE'])
})

it('does not claim acknowledgement when no warning can be shown', async () => {
  expect(await confirmWarnings([])).toBe(false)
  expect(await confirmWarnings(['UNKNOWN_MAPPING_WARNING'])).toBe(false)
})
