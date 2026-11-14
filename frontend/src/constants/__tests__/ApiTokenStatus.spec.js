import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  API_TOKEN_STATUSES,
  INACTIVE_STATUSES,
  USABLE_STATUSES,
  daysUntil,
  grantedRoleLabel,
  grantedRoleTagType,
  roleValueLabel,
  presetExpiry,
  privilegeLevel,
  splitTokens,
  summarize,
  latestUse,
} from '../apiTokens'
import { roleAdmin, roleAsset, roleSecurity, standardTokens } from '@/__fixtures__/apiTokens'

// 值域硬拷後端回應契約（API token 清單投影的 status 七個值）。後端改值時此處與契約一起更新
const CONTRACT_STATUSES = [
  'active',
  'expiring_soon',
  'expired',
  'revoked',
  'invalidated_by_restore',
  'suspended_account_disabled',
  'suspended_roles_revoked',
]

const LOCALES = ['zh-TW', 'en-US', 'ja-JP'].map((l) => [
  l,
  JSON.parse(readFileSync(join(process.cwd(), `src/i18n/locales/${l}.json`), 'utf8')),
])

describe('API token 狀態值域與呈現', () => {
  it('前端值域與回應契約互為全集', () => {
    expect([...API_TOKEN_STATUSES].sort()).toEqual([...CONTRACT_STATUSES].sort())
  })

  it('每個狀態三語都有非空的顯示文字', () => {
    for (const [locale, messages] of LOCALES) {
      for (const status of API_TOKEN_STATUSES) {
        const value = messages.apiTokens?.status?.[status]
        expect(typeof value === 'string' && value.length > 0, `${locale}:${status}`).toBe(true)
      }
    }
  })

  it('已失效與可用兩組互不重疊，暫停狀態兩組都不屬於', () => {
    for (const s of USABLE_STATUSES) expect(INACTIVE_STATUSES.has(s)).toBe(false)
    expect(USABLE_STATUSES.has('suspended_account_disabled')).toBe(false)
    expect(INACTIVE_STATUSES.has('suspended_roles_revoked')).toBe(false)
  })

  it('分區與摘要只看後端給的狀態', () => {
    const { current, inactive } = splitTokens(standardTokens())
    expect(current.map((t) => t.id)).toEqual([1, 2, 3])
    expect(inactive.map((t) => t.id)).toEqual([4, 5])
    expect(summarize(standardTokens())).toEqual({ usable: 3, expiringSoon: 1, inactive: 2, revocable: 3 })
  })

  it('已失效區依各自的失效時刻排序：撤銷看撤銷時刻，不被未來的到期日帶到前面', () => {
    const tokens = [
      // 較早撤銷、到期日遠在未來
      { id: 11, status: 'revoked', created_at: '2026-11-01T00:00:00Z', revoked_at: '2026-11-13T04:52:00Z', expires_at: '2027-11-01T00:00:00Z' },
      // 較晚撤銷、永不到期
      { id: 12, status: 'revoked', created_at: '2026-11-13T04:59:00Z', revoked_at: '2026-11-13T05:00:00Z', expires_at: null },
      // 到期時刻介於兩者之間
      { id: 13, status: 'expired', created_at: '2026-10-01T00:00:00Z', revoked_at: null, expires_at: '2026-11-13T04:55:00Z' },
      // 還原後失效：沒有失效時刻，退回建立時刻
      { id: 14, status: 'invalidated_by_restore', created_at: '2026-11-02T00:00:00Z', revoked_at: null, expires_at: '2027-01-01T00:00:00Z' },
    ]
    expect(splitTokens(tokens).inactive.map((t) => t.id)).toEqual([12, 13, 11, 14])
  })

  it('最近使用取所有 token 中最新的一筆，都沒用過為 null', () => {
    expect(latestUse(standardTokens())).toBe('2026-11-13T05:58:02Z')
    expect(latestUse([{ last_used_at: null }])).toBeNull()
  })

  it('預設期限換算成當天 23:59:59（本地時間）', () => {
    const now = new Date(2026, 10, 13, 9, 30, 0)
    const d = presetExpiry('d90', now)
    expect([d.getFullYear(), d.getMonth(), d.getDate(), d.getHours(), d.getMinutes(), d.getSeconds()]).toEqual([2027, 1, 11, 23, 59, 59])
    const y = presetExpiry('y1', now)
    expect([y.getFullYear(), y.getMonth(), y.getDate()]).toEqual([2027, 10, 13])
    expect(presetExpiry('never', now)).toBeNull()
  })

  it('天數以日曆日計算', () => {
    const now = new Date(2026, 10, 13, 22, 0, 0).getTime()
    expect(daysUntil(new Date(2026, 10, 16, 23, 59, 59).toISOString(), now)).toBe(3)
    expect(daysUntil(new Date(2026, 10, 13, 23, 59, 59).toISOString(), now)).toBe(0)
  })

  it('授權角色含超級管理者或系統安全管理員才算高權限', () => {
    expect(privilegeLevel([roleAsset()])).toBe('')
    expect(privilegeLevel([roleAsset(), roleSecurity()])).toBe('security')
    expect(privilegeLevel([roleSecurity(), roleAdmin()])).toBe('super')
  })

  it('超級管理者的範本識別是 super_admin：顯示名與標籤色仍對到管理員', () => {
    expect(roleAdmin().builtin_key).toBe('super_admin')
    expect(grantedRoleLabel(roleAdmin())).toBe('管理員')
    expect(grantedRoleTagType(roleAdmin())).toBe('danger')
    expect(roleValueLabel('super_admin')).toBe('管理員')
    expect(roleValueLabel('asset_admin')).toBe('資產管理員')
    expect(roleValueLabel('ci-reader')).toBe('ci-reader')
  })
})
