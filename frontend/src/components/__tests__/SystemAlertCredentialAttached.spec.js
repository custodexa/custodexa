import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import SystemAlertDetailDrawer from '@/components/system-alert/SystemAlertDetailDrawer.vue'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'
import i18n from '@/i18n'

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

// 與後端一致：單筆目標為資產、參數帶憑證與資產名稱；匯入目標為操作者、參數帶台數與憑證數
const single = (params = {}, over = {}) => ({
  alert_id: 91,
  alert_type: 'api_token_credential_attached',
  group: 'identity_privilege',
  severity: 'medium',
  triggered_at: '2026-11-14T09:12:30Z',
  actor: 'ops-chen',
  actor_user_id: 14,
  target_kind: 'asset',
  target_id: '42',
  client_ip: '203.0.113.10',
  params: {
    token_name: 'tf-prod',
    entry: 'bind',
    credential_name: 'linux-root-shared',
    asset_name: 'web-07',
    ...params,
  },
  deliveries: [],
  ...over,
})

const imported = (params = {}, over = {}) =>
  single(
    {},
    {
      target_kind: 'user',
      target_id: '14',
      request_id: '6f1c2b9e-0d4a-4c1e-9b7a-2f5e8d3c1a00',
      params: { token_name: 'tf-prod', entry: 'import', asset_count: '6', credential_count: '2', ...params },
      ...over,
    },
  )

const q = (sel) => document.body.querySelector(sel)
const text = (sel) => q(sel)?.textContent.replace(/[\s\u00a0\u202f]+/g, ' ').trim()

const mountDrawer = async () => {
  const w = mount(SystemAlertDetailDrawer, {
    props: { modelValue: true, alertId: 91 },
    attachTo: document.body,
    global: { plugins: [ElementPlus], stubs: { RouterLink: RouterLinkStub, 'router-link': RouterLinkStub } },
  })
  await flushPromises()
  return w
}

describe('系統告警明細：以 API token 掛載既有憑證', () => {
  beforeEach(() => {
    getDetailMock.mockReset()
    resetCapabilities()
  })
  afterEach(() => resetCapabilities())

  it('單筆：第一層一句話、專屬警示、掛載內容逐列列出', async () => {
    setCapabilitiesForTests(['asset:manage'])
    getDetailMock.mockResolvedValue(single())
    await mountDrawer()
    expect(text('[data-test="sa-first-layer"]')).toBe(
      'ops-chen 以 API token「tf-prod」把憑證「linux-root-shared」掛到資產「web-07」',
    )
    expect(text('[data-test="sa-attach-warning"]')).toContain('這筆憑證之後會用來登入這台資產')
    expect(text('[data-test="sa-attach-warning"]')).toContain('請確認位址正確，且這次掛載經過核准。')
    expect(text('[data-test="sa-attach"] h4')).toBe('掛載內容')
    expect(text('[data-test="sa-attach-operator"]')).toBe('ops-chen（使用者 #14）')
    expect(text('[data-test="sa-attach-token"]')).toBe('tf-prod')
    expect(text('[data-test="sa-attach-credential"]')).toBe('linux-root-shared（共用憑證）')
    expect(text('[data-test="sa-attach-asset"]')).toBe('web-07')
    expect(text('[data-test="sa-attach-entry"]')).toBe('掛到資產')
    expect(q('[data-test="sa-attach-asset-count"]')).toBeNull()
  })

  it('單筆：五種掛載方式各有說法', async () => {
    const cases = {
      asset_create: '建立資產時引用',
      account_create: '建立資產帳號時引用',
      bind: '掛到資產',
      rebind: '更換憑證',
    }
    for (const [entry, label] of Object.entries(cases)) {
      getDetailMock.mockResolvedValue(single({ entry }))
      const w = await mountDrawer()
      expect(text('[data-test="sa-attach-entry"]')).toBe(label)
      w.unmount()
    }
  })

  it('單筆：連結開該資產的編輯框；不能進資產頁時不呈現', async () => {
    setCapabilitiesForTests(['asset:manage'])
    getDetailMock.mockResolvedValue(single())
    await mountDrawer()
    const link = q('[data-test="sa-attach-link"]')
    expect(link.textContent.trim()).toBe('查看 web-07 的帳號')
    expect(JSON.parse(link.getAttribute('data-to'))).toEqual({ path: '/assets', query: { edit: '42' } })
  })

  it('單筆：目標識別不合法時不呈現連結', async () => {
    setCapabilitiesForTests(['asset:manage'])
    getDetailMock.mockResolvedValue(single({}, { target_id: '0' }))
    await mountDrawer()
    expect(q('[data-test="sa-attach-link"]')).toBeNull()
  })

  it('單筆：明細沒有操作者的使用者編號時只顯示名稱', async () => {
    getDetailMock.mockResolvedValue(single({}, { actor_user_id: 0 }))
    await mountDrawer()
    expect(text('[data-test="sa-attach-operator"]')).toBe('ops-chen')
  })

  it('匯入：只寫台數與憑證數，操作者帶使用者編號，連結以請求識別篩選操作日誌', async () => {
    setCapabilitiesForTests(['asset:manage', 'audit:view'])
    getDetailMock.mockResolvedValue(imported())
    await mountDrawer()
    expect(text('[data-test="sa-first-layer"]')).toBe(
      'ops-chen 以 API token「tf-prod」匯入資產，其中 6 台引用了 2 筆系統已保存的憑證',
    )
    expect(text('[data-test="sa-attach-warning"]')).toContain('這些憑證之後會用來登入這些資產')
    expect(text('[data-test="sa-attach"] h4')).toBe('匯入內容')
    expect(text('[data-test="sa-attach-operator"]')).toBe('ops-chen（使用者 #14）')
    expect(text('[data-test="sa-attach-asset-count"]')).toBe('6 台')
    expect(text('[data-test="sa-attach-credential-count"]')).toBe('2 筆')
    expect(text('[data-test="sa-attach-entry"]')).toBe('匯入資產')
    expect(q('[data-test="sa-attach-credential"]')).toBeNull()
    const link = q('[data-test="sa-attach-link"]')
    expect(link.textContent.trim()).toBe('在操作日誌查看這次匯入的每一台資產')
    expect(JSON.parse(link.getAttribute('data-to'))).toEqual({
      path: '/audit-logs',
      query: { tab: 'logs', request_id: '6f1c2b9e-0d4a-4c1e-9b7a-2f5e8d3c1a00' },
    })
  })

  it('匯入：明細沒有請求識別，或不能進操作日誌時不呈現連結', async () => {
    setCapabilitiesForTests(['asset:manage', 'audit:view'])
    getDetailMock.mockResolvedValue(imported({}, { request_id: '' }))
    let w = await mountDrawer()
    expect(q('[data-test="sa-attach-link"]')).toBeNull()
    w.unmount()
    setCapabilitiesForTests(['asset:manage'])
    getDetailMock.mockResolvedValue(imported())
    w = await mountDrawer()
    expect(q('[data-test="sa-attach-link"]')).toBeNull()
  })

  it('英文：憑證後的提示用半形括號；警示與連結對操作日誌同一叫法', async () => {
    setCapabilitiesForTests(['asset:manage', 'audit:view'])
    const prev = i18n.global.locale.value
    i18n.global.locale.value = 'en-US'
    try {
      getDetailMock.mockResolvedValue(single())
      let w = await mountDrawer()
      expect(text('[data-test="sa-attach-credential"]')).toBe('linux-root-shared (shared credential)')
      expect(text('[data-test="sa-attach-operator"]')).toBe('ops-chen (user #14)')
      w.unmount()
      getDetailMock.mockResolvedValue(imported())
      w = await mountDrawer()
      const warn = text('[data-test="sa-attach-warning"]')
      const link = text('[data-test="sa-attach-link"]')
      expect(link).toContain('operation log')
      expect(warn).toContain('operation log')
      expect(warn).not.toContain('audit log')
    } finally {
      i18n.global.locale.value = prev
    }
  })

  it('日文與中文：憑證後的提示用全形括號', async () => {
    const prev = i18n.global.locale.value
    try {
      for (const [locale, want] of [['zh-TW', 'linux-root-shared（共用憑證）'], ['ja-JP', 'linux-root-shared（共有認証情報）']]) {
        i18n.global.locale.value = locale
        getDetailMock.mockResolvedValue(single())
        const w = await mountDrawer()
        expect(text('[data-test="sa-attach-credential"]')).toBe(want)
        w.unmount()
      }
    } finally {
      i18n.global.locale.value = prev
    }
  })

  it('其他告警類型不出現掛載區塊', async () => {
    getDetailMock.mockResolvedValue(single({}, { alert_type: 'privileged_api_token_created', target_kind: 'user' }))
    await mountDrawer()
    expect(q('[data-test="sa-attach"]')).toBeNull()
    expect(q('[data-test="sa-attach-warning"]')).toBeNull()
  })
})
