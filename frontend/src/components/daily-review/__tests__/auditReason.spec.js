import { describe, it, expect, afterEach } from 'vitest'
import { setLanguage } from '@/i18n'
import { logDetailBlocks, reasonLines, reasonText } from '../auditReason'

// 擋：原因欄空白，或把 i18n 鍵、機器碼原樣印給簽核人
const expectReadable = (text) => {
  expect(typeof text).toBe('string')
  expect(text.trim()).not.toBe('')
  expect(text).not.toContain('dailyReview.reason.')
}

describe('reasonText', () => {
  afterEach(() => {
    setLanguage('zh-TW')
  })

  it('有碼：查譯並翻譯清除對象', () => {
    const text = reasonText({
      reason_code: 'retention_purge',
      reason_params: { target: 'audit_logs', days: '180', deleted: '42' },
      action: 'delete',
      resource: 'retention',
    })
    expectReadable(text)
    expect(text).toBe('保留期限清除：操作日誌超過 180 天的資料，刪除 42 筆')
  })

  it('有碼：含點的事件碼直接接在前綴後查', () => {
    const text = reasonText({ reason_code: 'event.ldap_directory_delete', action: 'delete', resource: 'ldap' })
    expect(text).toBe('刪除目錄服務設定')
  })

  it('未知碼（前端版本早於後端）退回 generic 句型，用該列的動作與資源', () => {
    const text = reasonText({ reason_code: 'brand_new_code', reason_params: { x: '1' }, action: 'delete', resource: 'asset' })
    expectReadable(text)
    expect(text).toBe('刪除資產')
    expect(text).not.toContain('brand_new_code')
  })

  it('沒有碼：照舊顯示 error_msg，其次 path', () => {
    expect(reasonText({ error_msg: 'connection refused', path: '/api/v1/assets/3', action: 'delete', resource: 'asset' }))
      .toBe('connection refused')
    expect(reasonText({ path: '/api/v1/assets/3', action: 'delete', resource: 'asset' })).toBe('/api/v1/assets/3')
  })

  it('沒有碼也沒有 error_msg／path：退回 generic，不得空白', () => {
    const text = reasonText({ action: 'update', resource: 'user' })
    expectReadable(text)
    expect(text).toBe('更新使用者')
    // 連動作與資源都沒有的極端列仍有可見文字
    expectReadable(reasonText({}))
    expectReadable(reasonText(null))
  })

  it('generic 碼的動作與資源走 enum 譯名，查不到顯示原值', () => {
    expect(reasonText({ reason_code: 'generic', reason_params: { action: 'delete', resource: 'mystery_res' } }))
      .toBe('刪除mystery_res')
    expect(reasonText({ reason_code: 'generic_event', reason_params: { action: 'update', resource: 'user', event: 'odd_event' } }))
      .toBe('更新使用者（事件：odd_event）')
  })

  it('清除對象查不到譯名時顯示原表名', () => {
    const text = reasonText({ reason_code: 'retention_purge_failed', reason_params: { target: 'future_table' } })
    expect(text).toBe('保留期限清除失敗：future_table')
  })

  it('角色名查得到顯示譯名，查不到（自訂角色）顯示原名，以語系分隔接回', () => {
    const item = { reason_code: 'role_mapping_applied', reason_params: { added: 'admin,唯讀稽核', removed: 'auditor' } }
    expect(reasonText(item)).toBe('外部登入時依群組映射調整角色：加上 管理員、唯讀稽核，移除 稽核人員')
    setLanguage('en-US')
    expect(reasonText(item)).toContain('Administrator, 唯讀稽核')
  })
})

describe('reasonLines', () => {
  afterEach(() => {
    setLanguage('zh-TW')
  })

  it('角色增減分兩行：主句＋「加上／移除」', () => {
    const lines = reasonLines({ reason_code: 'role_mapping_applied', reason_params: { added: 'admin', removed: '唯讀稽核' } })
    expect(lines.main).toBe('外部登入時依群組映射調整角色')
    expect(lines.sub).toEqual(['加上：管理員', '移除：唯讀稽核'])
  })

  it('只有加上時第二行只列加上，不出現空的「移除：」', () => {
    const lines = reasonLines({ reason_code: 'role_mapping_applied_added', reason_params: { added: 'auditor' } })
    expect(lines.sub).toEqual(['加上：稽核人員'])
  })

  it('其他碼只有一行，與 reasonText 相同', () => {
    const item = { reason_code: 'auto_disabled_inactive_account', reason_params: { days: '90' } }
    expect(reasonLines(item)).toEqual({ main: reasonText(item), sub: [] })
    expect(reasonLines({ path: '/api/v1/x' })).toEqual({ main: '/api/v1/x', sub: [] })
  })
})

describe('logDetailBlocks', () => {
  it('有 changes：只列變更，不列原因與原始內容', () => {
    const blocks = logDetailBlocks({ details: JSON.stringify({ changes: [{ field: 'name', old: 'a', new: 'b' }] }) })
    expect(blocks.changes).toHaveLength(1)
    expect(blocks.showReason).toBe(false)
    expect(blocks.raw).toBe('')
  })

  it('沒有 changes：列原因與格式化的 details', () => {
    const blocks = logDetailBlocks({ reason_code: 'retention_purge', details: '{"target":"audit_logs","deleted":3}' })
    expect(blocks.changes).toEqual([])
    expect(blocks.showReason).toBe(true)
    expect(blocks.raw).toBe('{\n  "target": "audit_logs",\n  "deleted": 3\n}')
  })

  it('details 不是 JSON 時原樣列出；沒有 details 也沒有碼時兩塊都不列', () => {
    expect(logDetailBlocks({ details: 'plain text' }).raw).toBe('plain text')
    expect(logDetailBlocks({ path: '/api/v1/assets' })).toEqual({ changes: [], showReason: false, raw: '' })
  })
})
