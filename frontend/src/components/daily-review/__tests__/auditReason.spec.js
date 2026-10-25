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

describe('角色指派類原因句', () => {
  afterEach(() => {
    setLanguage('zh-TW')
  })

  const assignNodes = {
    reason_code: 'user_role_assign_nodes',
    reason_params: { role: 'asset_admin', target: 'ops-lee', origin: 'api', nodes: 'SIT / ELK', nodes_count: '1' },
  }

  it.each([
    ['zh-TW', '把角色「資產管理員」指派給 ops-lee，限定節點：SIT / ELK（共 1 個節點）（管理介面操作）'],
    ['en-US', 'Assigned role "Asset administrator" to ops-lee, limited to nodes: SIT / ELK (1 nodes) (admin console)'],
    ['ja-JP', 'ロール「資産管理者」を ops-lee に割り当て、ノードを限定：SIT / ELK（計 1 ノード）（管理画面での操作）'],
  ])('限節點指派：內建角色鍵翻成該語系名稱（%s）', (lang, expected) => {
    setLanguage(lang)
    const text = reasonText(assignNodes)
    expectReadable(text)
    expect(text).not.toContain('asset_admin')
    expect(text).not.toContain('{')
    expect(text).toBe(expected)
  })

  it('全系統指派、移除與來路都翻成文字', () => {
    expect(reasonText({ reason_code: 'user_role_assign', reason_params: { role: 'auditor', target: 'ops-lee', origin: 'oidc' } }))
      .toBe('把角色「稽核人員」指派給 ops-lee（OIDC 首次登入）')
    expect(reasonText({ reason_code: 'user_role_revoke', reason_params: { role: 'auditor', target: 'ops-lee', origin: 'mapping' } }))
      .toBe('移除 ops-lee 的角色「稽核人員」（外部群組映射）')
  })

  it('身分管理員等不在 enum.role 的內建角色也有名稱', () => {
    const text = reasonText({ reason_code: 'user_role_revoke', reason_params: { role: 'identity_admin', target: 'ops-lee', origin: 'api' } })
    expect(text).toContain('身分管理員')
    expect(text).not.toContain('identity_admin')
  })

  it('自訂角色顯示其名稱；已刪除而查不到的角色顯示 #編號', () => {
    expect(reasonText({ reason_code: 'user_role_revoke', reason_params: { role: 'ELK 唯讀', target: 'ops-lee', origin: 'api' } }))
      .toContain('「ELK 唯讀」')
    expect(reasonText({ reason_code: 'user_role_revoke', reason_params: { role: '#42', target: '#9', origin: 'api' } }))
      .toBe('移除 #9 的角色「#42」（管理介面操作）')
  })

  it('群組列：對象顯示為「使用者群組 {名}」', () => {
    expect(reasonText({
      reason_code: 'user_group_role_assign',
      reason_params: { role: 'auditor', target: 'prod-assets' },
    })).toBe('把角色「稽核人員」指派給使用者群組 prod-assets')
  })

  it('只改範圍：前後範圍，global 顯示全系統，截斷時總數用實際數量', () => {
    const base = { reason_code: 'event.role_binding_range_changed' }
    expect(reasonText({ ...base, reason_params: {
      role: 'asset_admin', target: 'ops-lee', target_kind: 'user', before: 'UAT', before_count: '1', after: 'SIT / ELK', after_count: '1' } }))
      .toBe('把 ops-lee 的角色「資產管理員」範圍由UAT（共 1 個節點）改為SIT / ELK（共 1 個節點）')
    expect(reasonText({ ...base, reason_params: {
      role: 'asset_admin', target: 'ops-lee', target_kind: 'user', before: 'UAT', before_count: '1', after: 'global', after_count: '0' } }))
      .toBe('把 ops-lee 的角色「資產管理員」範圍由UAT（共 1 個節點）改為全系統')
    const many = Array.from({ length: 100 }, (_, i) => `#${i + 1}`).join(',')
    const text = reasonText({ ...base, reason_params: {
      role: 'auditor', target: 'prod-assets', target_kind: 'user_group', before: 'global', after: many, after_count: '150' } })
    expect(text).toContain('範圍由全系統改為')
    expect(text).toContain('（共 150 個節點）')
    expect(text).toContain('使用者群組 prod-assets')
    expect(text).not.toContain('{')
  })

  it('授權分級列：標記逐項翻譯，且不聲稱已通知', () => {
    expect(reasonText({ reason_code: 'event.grant_change_graded', reason_params: { marks: 'management_grant' } }))
      .toBe('這次授權變更已建立系統告警：管理類發放')
    expect(reasonText({ reason_code: 'event.grant_change_graded', reason_params: { marks: 'self_authorization,management_grant' } }))
      .toBe('這次授權變更已建立系統告警：自我授權、管理類發放')
    setLanguage('en-US')
    expect(reasonText({ reason_code: 'event.grant_change_graded', reason_params: { marks: 'management_grant' } }))
      .toBe('This authorization change raised a system alert: Management grant')
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
