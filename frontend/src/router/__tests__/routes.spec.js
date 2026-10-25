import { describe, it, expect } from 'vitest'
import router from '../index'
import { ADMIN_PERMISSIONS, AUDITOR_PERMISSIONS, USER_PERMISSIONS } from '@/composables/__tests__/capabilityFixtures'
import { canEnter, entryRuleFor } from '../entryRules'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'

// 入口規則改為 meta.permissionsAll（需持有清單內每一個權限點）。
// 「誰進得去」以內建範本的權限集合判定：哪些範本持有該入口要求的每一個鍵。
const holders = (meta) => {
  const need = meta.permissionsAll
  expect(Array.isArray(need) && need.length > 0).toBe(true)
  const templates = { admin: ADMIN_PERMISSIONS, auditor: AUDITOR_PERMISSIONS, user: USER_PERMISSIONS }
  return Object.keys(templates).filter((name) => need.every((p) => templates[name].includes(p)))
}

// 路由註冊面——新頁 admin-only、
// 更名頁原路徑不變（書籤/深連結不失效）
describe('存取控管與傳輸清冊的路由註冊', () => {
  it('/access-control 已註冊且為 admin-only', () => {
    const resolved = router.resolve('/access-control')
    expect(resolved.name).toBe('AccessControl')
    expect(resolved.meta.requiresAuth).toBe(true)
    expect(holders(resolved.meta)).toEqual(['admin'])
  })

  it('更名後 /transmission-inventory 原路徑照常解析（深連結不失效）', () => {
    const resolved = router.resolve('/transmission-inventory')
    expect(resolved.name).toBe('TransmissionInventory')
    expect(holders(resolved.meta)).toEqual(['admin'])
  })
})

// 輪替證據：權限沿稽核頁模式（後端的 audit:view 閘），
// 排程管理不另立路由——它是頁內的 admin 專屬區塊
describe('輪替證據的路由註冊', () => {
  it('/rotation-evidence 已註冊且限 admin/auditor', () => {
    const resolved = router.resolve('/rotation-evidence')
    expect(resolved.name).toBe('RotationEvidence')
    expect(resolved.meta.requiresAuth).toBe(true)
    expect(holders(resolved.meta)).toEqual(['admin', 'auditor'])
  })

  it('下載中心的路徑與名稱不因新增分頁而改變（書籤不失效）', () => {
    const resolved = router.resolve('/audit/exports')
    expect(resolved.name).toBe('AuditExports')
    expect(holders(resolved.meta)).toEqual(['admin', 'auditor'])
  })
})

// 帳號憑證庫：持任一憑證語義能力（含只讀檢視）即可進入，內建範本中只有 admin 持有。
// 路由第一段同時登記於後端的前端路由段枚舉（雙向守衛），漏登記的症狀是
// SSO 登入後被丟回首頁
describe('帳號憑證庫的路由註冊', () => {
  it('/credentials 已註冊，入口為憑證語義能力任一，內建範本只有 admin 持有', () => {
    const resolved = router.resolve('/credentials')
    expect(resolved.name).toBe('CredentialLibrary')
    expect(resolved.meta.requiresAuth).toBe(true)
    expect(resolved.meta.permissionsAll).toBeUndefined()
    expect([...resolved.meta.permissionsAny].sort()).toEqual([
      'credential:bind', 'credential:convert-scope', 'credential:create', 'credential:delete',
      'credential:detach', 'credential:manage', 'credential:rotate', 'credential:set-secret',
      'credential:update', 'credential:view',
    ])
    const templates = { admin: ADMIN_PERMISSIONS, auditor: AUDITOR_PERMISSIONS, user: USER_PERMISSIONS }
    const anyHolders = Object.keys(templates)
      .filter((name) => resolved.meta.permissionsAny.some((p) => templates[name].includes(p)))
    expect(anyHolders).toEqual(['admin'])
  })

  it('只持單一語義能力（或只讀檢視）的自訂角色可進入；毫無憑證能力被擋', () => {
    const rule = entryRuleFor('/credentials')
    for (const perm of ['credential:view', 'credential:bind', 'credential:rotate', 'credential:set-secret']) {
      setCapabilitiesForTests(['asset:view', perm])
      expect(canEnter(rule), perm).toBe(true)
    }
    setCapabilitiesForTests(['asset:view', 'account:rotate', 'changesecret:manage'])
    expect(canEnter(rule)).toBe(false)
    resetCapabilities()
  })

  it('既有改密兩頁的路徑與名稱不因新增本頁而改變（書籤不失效）', () => {
    expect(router.resolve('/change-secret-plans').name).toBe('ChangeSecretPlans')
    expect(router.resolve('/change-secret-batches').name).toBe('AccountBatchRotation')
  })
})

// 守衛攔下頁：**不得帶 requiresAuth**。攔下模式的路由樹上沒有登入端點，
// 帶了就是把唯一的救援路徑導去一個不存在的頁面（解封頁同理）
describe('守衛攔下頁的路由註冊', () => {
  it('/instance-guard 已註冊且不要求登入、不限角色', () => {
    const resolved = router.resolve('/instance-guard')
    expect(resolved.name).toBe('InstanceGuardHalted')
    expect(resolved.meta.requiresAuth).toBeUndefined()
    expect(resolved.meta.permissionsAll).toBeUndefined()
    expect(resolved.meta.signedIn).toBeUndefined()
  })

  it('解封頁的路徑與名稱不因新增本頁而改變', () => {
    const resolved = router.resolve('/unseal')
    expect(resolved.name).toBe('Unseal')
    expect(resolved.meta.requiresAuth).toBeUndefined()
  })
})

// 政策組與合規對照：權限不對稱是刻意的。判定結果 admin 與 auditor 看的是同一份，
// 而條文的寫入面只對 admin 開——auditor 進得去就等於稽核者可以改自己要稽核的依據
describe('政策組與合規對照的路由註冊', () => {
  it('/compliance-map 已註冊且 admin 與 auditor 皆可讀', () => {
    const resolved = router.resolve('/compliance-map')
    expect(resolved.name).toBe('ComplianceMap')
    expect(resolved.meta.requiresAuth).toBe(true)
    expect(holders(resolved.meta)).toEqual(['admin', 'auditor'])
  })

  it('/policy-groups 已註冊且為 admin-only', () => {
    const resolved = router.resolve('/policy-groups')
    expect(resolved.name).toBe('PolicyGroups')
    expect(resolved.meta.requiresAuth).toBe(true)
    expect(holders(resolved.meta)).toEqual(['admin'])
  })

  it('安全政策頁的路徑與名稱不因新增兩頁而改變（書籤不失效）', () => {
    expect(router.resolve('/security-policies').name).toBe('SecurityPolicies')
    expect(router.resolve('/audit-logs').name).toBe('AuditLogs')
  })
})
