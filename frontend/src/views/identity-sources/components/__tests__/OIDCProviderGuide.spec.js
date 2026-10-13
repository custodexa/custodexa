import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import i18n from '@/i18n'
import OIDCProviderGuide from '../OIDCProviderGuide.vue'
import OIDCSourceDetail from '../../OIDCSourceDetail.vue'
import { createOIDCProvider, updateOIDCProvider } from '@/api/oidc'

enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const route = { params: {} }
vi.mock('vue-router', () => ({
  useRoute: () => route,
  useRouter: () => ({ replace: vi.fn() }),
}))

const getDetailMock = vi.fn()
const previewMock = vi.fn(() => new Promise(() => {}))
vi.mock('@/api/identitySources', () => ({
  getOIDCProviderDetail: (...a) => getDetailMock(...a),
  previewOIDCDiscovery: (...a) => previewMock(...a),
  isNotImplemented: () => false,
  getSourceStatus: vi.fn(() => Promise.resolve({})),
  errorCode: () => '',
  CODE_LDAP_DIRECTORY_NOT_FOUND: 'LDAP_DIRECTORY_NOT_FOUND',
  getIdentitySources: vi.fn(() => Promise.resolve({ data: [] })),
}))

vi.mock('@/api/oidc', () => ({
  createOIDCProvider: vi.fn(),
  updateOIDCProvider: vi.fn(),
}))

vi.mock('@/api/user', () => ({
  getRoleList: vi.fn(() => Promise.resolve({ data: [] })),
}))

const t = (key) => i18n.global.t(key)

// 每家各取一句只屬於它的說明作為辨識
const MARKERS = {
  entra: 'identitySources.oidc.guide.entra.issuer', // Directory (tenant) ID 句
  google: 'identitySources.oidc.guide.google.restrict', // Internal 句
  other: 'identitySources.oidc.guide.other.flow', // PKCE 句
}

const mountGuide = (provider) =>
  mount(OIDCProviderGuide, {
    props: { provider, open: true },
    global: { plugins: [ElementPlus] },
  })

const mountPage = () =>
  mount(OIDCSourceDetail, {
    global: {
      plugins: [ElementPlus],
      stubs: { 'router-link': { template: '<a><slot /></a>' } },
    },
  })

describe('OIDCProviderGuide：三家各自只顯示自己的說明', () => {
  for (const provider of Object.keys(MARKERS)) {
    it(`${provider}`, () => {
      const text = mountGuide(provider).text()
      for (const [other, key] of Object.entries(MARKERS)) {
        if (other === provider) expect(text, key).toContain(t(key))
        else expect(text, key).not.toContain(t(key))
      }
    })
  }

  it('Entra 的說明含目錄（租用戶）識別碼、Google 的含 Internal、其他 OIDC 的含 PKCE', () => {
    expect(mountGuide('entra').text()).toContain('Directory (tenant) ID')
    expect(mountGuide('google').text()).toContain('Internal')
    expect(mountGuide('other').text()).toContain('PKCE')
  })
})

describe('OIDCSourceDetail 的提供者選擇器', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    route.params = {}
    createOIDCProvider.mockResolvedValue({ data: { id: 31 } })
    updateOIDCProvider.mockResolvedValue({ data: { id: 32 } })
  })

  it('新增頁預設其他 OIDC；選 Google 後 issuer 填入 https://accounts.google.com 並自動探索', async () => {
    const wrapper = mountPage()
    await flushPromises()
    expect(wrapper.vm.provider).toBe('other')

    await wrapper.find('[data-test="provider-option-google"]').trigger('click')
    await flushPromises()

    expect(wrapper.vm.form.issuer).toBe('https://accounts.google.com')
    expect(previewMock).toHaveBeenCalledWith('https://accounts.google.com')
  })

  const DERIVE = [
    ['https://login.microsoftonline.com/00000000-1111-2222-3333-444444444444/v2.0', 'entra'],
    ['https://accounts.google.com', 'google'],
    ['accounts.google.com', 'google'],
    ['https://idp.example.com', 'other'],
  ]
  for (const [issuer, expected] of DERIVE) {
    it(`編輯頁依 issuer 帶出：${issuer} → ${expected}；改選不改 issuer`, async () => {
      route.params = { id: '40' }
      getDetailMock.mockResolvedValue({
        name: 'corp', issuer, client_id: 'cid', scopes: 'openid profile email',
        admission_mode: 'prebound_only', admission_rules: '{}', has_secret: true, enabled: false,
        issuer_kind: 'shared', issuer_kind_source: 'unknown_default',
      })
      const wrapper = mountPage()
      await flushPromises()

      expect(wrapper.vm.provider).toBe(expected)
      expect(wrapper.find('[data-test="provider-guide"]').attributes('data-provider')).toBe(expected)

      await wrapper.find('[data-test="provider-option-google"]').trigger('click')
      await flushPromises()
      expect(wrapper.vm.form.issuer).toBe(issuer)
    })
  }

  it('建立與更新的請求都不含選擇器的值', async () => {
    const wrapper = mountPage()
    await flushPromises()
    await wrapper.find('[data-test="provider-option-entra"]').trigger('click')
    wrapper.vm.form.name = 'corp'
    wrapper.vm.form.issuer = 'https://login.microsoftonline.com/00000000-1111-2222-3333-444444444444/v2.0'
    wrapper.vm.form.client_id = 'cid'
    await wrapper.vm.handleSave(true)
    await flushPromises()

    const created = createOIDCProvider.mock.calls[0][0]
    expect(Object.keys(created)).not.toContain('provider')
    expect(Object.values(created)).not.toContain('entra')
    wrapper.unmount()

    route.params = { id: '41' }
    getDetailMock.mockResolvedValue({
      name: 'corp', issuer: 'https://accounts.google.com', client_id: 'cid', scopes: 'openid profile email',
      admission_mode: 'prebound_only', admission_rules: '{}', has_secret: true, enabled: false,
      issuer_kind: 'shared', issuer_kind_source: 'builtin_list',
    })
    const edit = mountPage()
    await flushPromises()
    await edit.vm.handleSave(true)
    await flushPromises()

    const updated = updateOIDCProvider.mock.calls[0][1]
    expect(Object.keys(updated)).not.toContain('provider')
    expect(Object.values(updated)).not.toContain('google')
  })
})
