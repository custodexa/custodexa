import { describe, it, expect } from 'vitest'
import router from '../index'

// 路由註冊面——新頁 admin-only、
// 更名頁原路徑不變（書籤/深連結不失效）
describe('存取控管與傳輸清冊的路由註冊', () => {
  it('/access-control 已註冊且為 admin-only', () => {
    const resolved = router.resolve('/access-control')
    expect(resolved.name).toBe('AccessControl')
    expect(resolved.meta.requiresAuth).toBe(true)
    expect(resolved.meta.roles).toEqual(['admin'])
  })

  it('更名後 /transmission-inventory 原路徑照常解析（深連結不失效）', () => {
    const resolved = router.resolve('/transmission-inventory')
    expect(resolved.name).toBe('TransmissionInventory')
    expect(resolved.meta.roles).toEqual(['admin'])
  })
})

// 輪替證據：權限沿稽核頁模式（後端的 audit:view 閘），
// 排程管理不另立路由——它是頁內的 admin 專屬區塊
describe('輪替證據的路由註冊', () => {
  it('/rotation-evidence 已註冊且限 admin/auditor', () => {
    const resolved = router.resolve('/rotation-evidence')
    expect(resolved.name).toBe('RotationEvidence')
    expect(resolved.meta.requiresAuth).toBe(true)
    expect(resolved.meta.roles).toEqual(['admin', 'auditor'])
  })

  it('下載中心的路徑與名稱不因新增分頁而改變（書籤不失效）', () => {
    const resolved = router.resolve('/audit/exports')
    expect(resolved.name).toBe('AuditExports')
    expect(resolved.meta.roles).toEqual(['admin', 'auditor'])
  })
})

// 帳號憑證庫：登入憑證的管理面，權限不得低於改資產，故 admin-only。
// 路由第一段同時登記於後端的前端路由段枚舉（雙向守衛），漏登記的症狀是
// SSO 登入後被丟回首頁
describe('帳號憑證庫的路由註冊', () => {
  it('/credentials 已註冊且為 admin-only', () => {
    const resolved = router.resolve('/credentials')
    expect(resolved.name).toBe('CredentialLibrary')
    expect(resolved.meta.requiresAuth).toBe(true)
    expect(resolved.meta.roles).toEqual(['admin'])
  })

  it('既有改密兩頁的路徑與名稱不因新增本頁而改變（書籤不失效）', () => {
    expect(router.resolve('/change-secret-plans').name).toBe('ChangeSecretPlans')
    expect(router.resolve('/change-secret-batches').name).toBe('AccountBatchRotation')
  })
})
