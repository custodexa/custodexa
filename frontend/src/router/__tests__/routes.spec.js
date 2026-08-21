import { describe, it, expect } from 'vitest'
import router from '../index'

// settings-domain-restructure 4.2：路由註冊面——新頁 admin-only、
// 更名頁原路徑不變（書籤/深連結不失效）
describe('settings-domain-restructure 路由註冊', () => {
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
