import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import SystemAlertDetailDrawer from '@/components/system-alert/SystemAlertDetailDrawer.vue'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'
import { formatDateTime } from '@/utils/format'

enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const getDetailMock = vi.fn()
vi.mock('@/api/systemAlerts', () => ({
  getSystemAlertDetail: (...args) => getDetailMock(...args),
}))

const RouterLinkStub = { props: ['to'], template: '<a :data-to="JSON.stringify(to)"><slot /></a>' }

const detail = (params = {}, over = {}) => ({
  alert_id: 77,
  alert_type: 'privileged_api_token_created',
  group: 'privilege',
  severity: 'high',
  triggered_at: '2026-11-13T05:20:44Z',
  actor: 'root-lin',
  target_kind: 'user',
  target_id: '3',
  client_ip: '10.20.1.8',
  // 與後端一致：建立者在明細頂層的 actor，參數不含 actor；內建角色以範本識別表示；
  // expiry 必帶（never＝永不到期，不帶 expires_at；at 時另帶 expires_at）
  params: {
    privileged_roles: 'super_admin',
    token_name: 'tf-bootstrap',
    granted_roles: 'super_admin,asset_admin',
    expiry: 'never',
    ...params,
  },
  deliveries: [],
  ...over,
})

const q = (sel) => document.body.querySelector(sel)
const text = (sel) => q(sel)?.textContent.replace(/[\s\u00a0\u202f]+/g, ' ').trim()

const mountDrawer = async () => {
  const w = mount(SystemAlertDetailDrawer, {
    props: { modelValue: true, alertId: 77 },
    attachTo: document.body,
    global: { plugins: [ElementPlus], stubs: { RouterLink: RouterLinkStub, 'router-link': RouterLinkStub } },
  })
  await flushPromises()
  return w
}

describe('系統告警明細：建立高權限 API token', () => {
  beforeEach(() => {
    getDetailMock.mockReset()
    resetCapabilities()
  })
  afterEach(() => resetCapabilities())

  it('第一層一句話寫出誰建立、含哪個高權限角色；建立內容逐列列出，永不到期加註', async () => {
    setCapabilitiesForTests(['user:manage'])
    getDetailMock.mockResolvedValue(detail())
    await mountDrawer()
    expect(text('[data-test="sa-first-layer"]')).toBe('root-lin 建立了一把 API token，授權角色含管理員（超級管理者）')
    expect(text('[data-test="sa-token-creator"]')).toBe('root-lin（使用者 #3）')
    expect(text('[data-test="sa-token-priv-roles"]')).toBe('管理員（超級管理者）')
    expect(text('[data-test="sa-token-name"]')).toBe('tf-bootstrap')
    expect(text('[data-test="sa-token-granted-roles"]')).toBe('管理員（超級管理者）、資產管理員')
    expect(text('[data-test="sa-token-expiry"]')).toBe('永不到期（不會自動失效）')
  })

  it('永不到期時參數沒有 expires_at 鍵：寫永不到期；自訂角色以名稱原樣顯示', async () => {
    getDetailMock.mockResolvedValue(detail({ privileged_roles: 'security_admin', granted_roles: 'security_admin,ci-reader' }))
    await mountDrawer()
    expect(Object.prototype.hasOwnProperty.call(getDetailMock.mock.results[0].value, 'expires_at')).toBe(false)
    expect(text('[data-test="sa-token-expiry"]')).toBe('永不到期（不會自動失效）')
    expect(text('[data-test="sa-token-granted-roles"]')).toBe('系統安全管理員、ci-reader')
  })

  it('有到期時間（expiry=at）：顯示格式化後的時間', async () => {
    getDetailMock.mockResolvedValue(detail({ expiry: 'at', expires_at: '2027-02-11T15:59:59Z' }))
    await mountDrawer()
    expect(text('[data-test="sa-token-expiry"]')).toBe(formatDateTime('2027-02-11T15:59:59Z').replace(/[\s\u00a0\u202f]+/g, ' '))
  })

  it('較早的告警沒有 expiry 鍵：以有無 expires_at 判斷', async () => {
    getDetailMock.mockResolvedValue(detail({ expiry: undefined, expires_at: '2027-02-11T15:59:59Z' }))
    await mountDrawer()
    expect(text('[data-test="sa-token-expiry"]')).toBe(formatDateTime('2027-02-11T15:59:59Z').replace(/[\s\u00a0\u202f]+/g, ' '))
  })

  it('expiry=never 時即使帶了 expires_at 也寫永不到期', async () => {
    getDetailMock.mockResolvedValue(detail({ expiry: 'never', expires_at: '2027-02-11T15:59:59Z' }))
    await mountDrawer()
    expect(text('[data-test="sa-token-expiry"]')).toBe('永不到期（不會自動失效）')
  })

  it('能進使用者管理：連到建立者的 API token 分頁', async () => {
    setCapabilitiesForTests(['user:manage'])
    getDetailMock.mockResolvedValue(detail())
    await mountDrawer()
    const link = q('[data-test="sa-view-api-tokens"]')
    expect(link.textContent.trim()).toBe('查看 root-lin 的 API token')
    expect(JSON.parse(link.getAttribute('data-to'))).toEqual({ path: '/users/3', query: { tab: 'apiTokens' } })
  })

  it('進不了使用者管理：不顯示連結，其餘照常', async () => {
    setCapabilitiesForTests([])
    getDetailMock.mockResolvedValue(detail())
    await mountDrawer()
    expect(q('[data-test="sa-view-api-tokens"]')).toBeNull()
    expect(q('[data-test="sa-token-created"]')).not.toBeNull()
  })

  it('其他型別不出現建立內容', async () => {
    getDetailMock.mockResolvedValue(detail({}, { alert_type: 'self_privilege_increased' }))
    await mountDrawer()
    expect(q('[data-test="sa-token-created"]')).toBeNull()
  })
})
