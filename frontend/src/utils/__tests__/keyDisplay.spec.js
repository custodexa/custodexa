import { describe, it, expect, afterEach } from 'vitest'
import i18n from '@/i18n'
import { keyEnvName, keyEnvNote } from '@/utils/keyDisplay'

// i18n 由 setupFiles 全域注入。切語言＝設 locale.value；每測後復位 zh-TW。
function setLocale(l) {
  i18n.global.locale.value = l
}
afterEach(() => setLocale('zh-TW'))

describe('keyEnvNote / keyEnvName — 當前語言查譯 + 降級', () => {
  const kek = {
    name: 'ENCRYPTION_KEY (KEK)',
    note: '信封主鑰：換鑰走精靈的 KEK 重包流程',
    note_code: 'encryption_key',
  }
  const ed = {
    name: '匯出簽章鑰 (Ed25519)',
    name_code: 'audit_export',
    note: '私鑰信封加密落庫；輪替需重發公鑰給外部驗證者（runbook）',
    note_code: 'audit_export',
  }

  it('zh：note_code 查譯得繁中（＝後端 fallback）', () => {
    expect(keyEnvNote(kek)).toBe('信封主鑰：換鑰走精靈的 KEK 重包流程')
  })

  it('en：切語言即得英文（getter 反應性）', () => {
    setLocale('en-US')
    expect(keyEnvNote(kek)).toContain('Envelope master key')
    expect(keyEnvName(ed)).toBe('Export Signing Key (Ed25519)')
  })

  it('無 name_code：用後端 name（技術識別字不譯）', () => {
    setLocale('en-US')
    expect(keyEnvName(kek)).toBe('ENCRYPTION_KEY (KEK)')
  })

  it('未知 code：降級後端 note，不露空字串', () => {
    setLocale('en-US')
    expect(keyEnvNote({ note: 'raw-zh-note', note_code: 'nonexistent_code' })).toBe('raw-zh-note')
  })

  it('無 code：直接用後端 note', () => {
    expect(keyEnvNote({ note: 'plain' })).toBe('plain')
    expect(keyEnvName({ name: 'X' })).toBe('X')
  })
})
