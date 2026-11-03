import { describe, it, expect } from 'vitest'
import {
  isWindowsFamily, isExecutorProtocol, executorSourceKey, EDIT_FOCUS_TARGETS,
  EXECUTOR_ERROR_TABLE, findExecutorError,
} from '../assetExecutor'

describe('assetExecutor constants', () => {
  it('rdp 與 ssh+windows_ssh 判為 Windows 族，ssh 無通道判為非 Windows 族', () => {
    expect(isWindowsFamily({ protocol: 'rdp' })).toBe(true)
    expect(isWindowsFamily({ protocol: 'ssh', rotation_channel: 'windows_ssh' })).toBe(true)
    expect(isWindowsFamily({ protocol: 'ssh' })).toBe(false)
    expect(isWindowsFamily({ protocol: 'ssh', rotation_channel: 'ssh' })).toBe(false)
    expect(isWindowsFamily(null)).toBe(false)
  })

  it('只有 ssh 與 rdp 可設定專用帳號', () => {
    expect(isExecutorProtocol('ssh')).toBe(true)
    expect(isExecutorProtocol('rdp')).toBe(true)
    expect(isExecutorProtocol('mysql')).toBe(false)
  })

  it('秘密來源字樣依 source，缺席時退回推斷', () => {
    expect(executorSourceKey({ source: 'generate' })).toBe('generate')
    expect(executorSourceKey({ source: 'convert' })).toBe('convert')
    expect(executorSourceKey({ source: 'inline', secret_type: 'password' })).toBe('inline')
    expect(executorSourceKey({ source: 'inline', secret_type: 'ssh_key' })).toBe('inlineKey')
    expect(executorSourceKey({ source: 'shared', credential: { shared_credential: true } })).toBe('shared')
    expect(executorSourceKey({ credential: { shared_credential: true, credential_out_of_scope: true } })).toBe('sharedOutOfScope')
    expect(executorSourceKey({ has_public_key: true })).toBe('generate')
    expect(executorSourceKey({ secret_type: 'password' })).toBe('dedicated')
  })

  it('EDIT_FOCUS_TARGETS 含 host-key 與 executor，每列都有 scroll', () => {
    expect(Object.keys(EDIT_FOCUS_TARGETS)).toEqual(expect.arrayContaining(['host-key', 'executor']))
    for (const t of Object.values(EDIT_FOCUS_TARGETS)) expect(typeof t.scroll).toBe('string')
  })

  it('錯誤對照表的列為「碼＋情境」且不重複', () => {
    const keys = EXECUTOR_ERROR_TABLE.map((r) => `${r.code}|${r.context}`)
    expect(new Set(keys).size).toBe(keys.length)
    expect(keys).toEqual([
      'CONFLICT_ACCOUNT_USERNAME|set',
      'RULE_EXECUTOR_SHARED_HOST_COUNT|set',
      'RULE_CREDENTIAL_PURPOSE_MISMATCH|set',
      'RULE_EXECUTOR_SECRET_TYPE_UNSUPPORTED|set',
      'RULE_EXECUTOR_CONVERT_CANDIDATE_PENDING|convert',
      'RULE_CREDENTIAL_ROTATION_ACTIVE|convert',
      'RULE_CREDENTIAL_OUT_OF_SYNC|convert',
      'RULE_CREDENTIAL_ROTATION_ACTIVE|replace',
      'RULE_CREDENTIAL_ROTATION_ACTIVE|clear',
      'RULE_EXECUTOR_STATE_CHANGED|any',
      'RULE_EXECUTOR_PROTOCOL_UNSUPPORTED|any',
      'VALIDATION_EXECUTOR_SOURCE_INVALID|any',
      'INTERNAL_ASSET_EXECUTOR_WRITE|any',
    ])
  })

  it('messageKey 為 apiError 或以 assetExecutor. 開頭', () => {
    for (const r of EXECUTOR_ERROR_TABLE) {
      expect(r.messageKey === 'apiError' || r.messageKey.startsWith('assetExecutor.')).toBe(true)
    }
  })

  it('findExecutorError 同碼不同情境取不同列，查無回 null', () => {
    expect(findExecutorError('RULE_CREDENTIAL_ROTATION_ACTIVE', 'convert').messageKey).toBe('assetExecutor.error.convertRotationActive')
    expect(findExecutorError('RULE_CREDENTIAL_ROTATION_ACTIVE', 'clear').messageKey).toBe('assetExecutor.error.clearRotationActive')
    expect(findExecutorError('RULE_EXECUTOR_STATE_CHANGED', 'clear').placement).toBe('reload')
    expect(findExecutorError('NOPE', 'set')).toBeNull()
  })
})
