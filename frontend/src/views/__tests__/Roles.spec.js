import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Roles from '../Roles.vue'
import i18n from '@/i18n'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

// happy-dom 的 MutationObserver 與 el-table key-render-helper 不相容
class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const getRoleListMock = vi.fn()

vi.mock('@/api/user', () => ({
  getRoleList: (...args) => getRoleListMock(...args),
}))

const seededRoles = [
  { id: 1, name: 'admin', description: '系統管理員，擁有所有權限', created_at: '2026-01-01T00:00:00Z' },
  { id: 2, name: 'auditor', description: '稽核人員，可以檢視所有審計日誌和連線記錄', created_at: '2026-01-01T00:00:00Z' },
]

const mountView = () =>
  mount(Roles, {
    global: { plugins: [ElementPlus] },
  })

describe('Roles 描述欄查譯（roles-description-i18n）', () => {
  beforeEach(() => {
    getRoleListMock.mockReset()
  })

  it('zh-TW：描述欄顯示 enum.role.*.description 譯文而非裸後端欄位', async () => {
    getRoleListMock.mockResolvedValue({ data: seededRoles })
    const wrapper = mountView()
    await flushPromises()

    const zhAdminDesc = i18n.global.t('enum.role.admin.description')
    expect(wrapper.text()).toContain(zhAdminDesc)
    // 後端 seed 原句不再出現於列表（譯文與後端欄位措辭不同，可區分來源）
    expect(wrapper.text()).not.toContain('系統管理員，擁有所有權限')
  })

  it('en-US：切語言後描述欄顯示英文譯文', async () => {
    i18n.global.locale.value = 'en-US'
    getRoleListMock.mockResolvedValue({ data: seededRoles })
    const wrapper = mountView()
    await flushPromises()

    const enAdminDesc = i18n.global.t('enum.role.admin.description')
    expect(enAdminDesc).toMatch(/^Full system permissions/)
    expect(wrapper.text()).toContain(enAdminDesc)
    expect(wrapper.text()).not.toContain('系統管理員，擁有所有權限')
  })

  it('未知（非 seeded）角色：描述欄降級顯示後端 description', async () => {
    getRoleListMock.mockResolvedValue({
      data: [
        ...seededRoles,
        { id: 9, name: 'operator', description: '自訂營運角色描述', created_at: '2026-01-01T00:00:00Z' },
      ],
    })
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('自訂營運角色描述')
  })
})
