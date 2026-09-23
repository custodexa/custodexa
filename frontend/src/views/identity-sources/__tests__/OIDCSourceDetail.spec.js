import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import i18n from '@/i18n'
import OIDCSourceDetail from '../OIDCSourceDetail.vue'

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

const route = { params: {} }
vi.mock('vue-router', () => ({
  useRoute: () => route,
  useRouter: () => ({ replace: vi.fn() }),
}))

const getDetailMock = vi.fn()
vi.mock('@/api/identitySources', () => ({
  getOIDCProviderDetail: (...a) => getDetailMock(...a),
  previewOIDCDiscovery: vi.fn(() => new Promise(() => {})),
  isNotImplemented: () => false,
  getSourceStatus: vi.fn(() => Promise.resolve({})),
  errorCode: () => '',
  CODE_LDAP_DIRECTORY_NOT_FOUND: 'LDAP_DIRECTORY_NOT_FOUND',
  getSourceMappings: vi.fn(() => Promise.resolve({ data: [] })),
  createSourceMapping: vi.fn(),
  updateSourceMapping: vi.fn(),
  deleteSourceMapping: vi.fn(),
}))

vi.mock('@/api/oidc', () => ({
  createOIDCProvider: vi.fn(),
  updateOIDCProvider: vi.fn(),
}))

vi.mock('@/api/user', () => ({
  getRoleList: vi.fn(() => Promise.resolve({ data: [] })),
}))

const t = (key) => i18n.global.t(key)

const ENTRA_ISSUER = 'https://login.microsoftonline.com/00000000-1111-2222-3333-444444444444/v2.0'
const OTHER_ISSUER = 'https://idp.example.com'

const ENTRA_FIELD_KEYS = [
  'identitySources.oidc.entra.issuer',
  'identitySources.oidc.entra.clientId',
  'identitySources.oidc.entra.secret',
  'identitySources.oidc.entra.groupsClaim',
  'identitySources.oidc.entra.tid',
  'identitySources.oidc.entra.emailDomain',
  'identitySources.oidc.entra.emailVerified',
  'identitySources.mapping.entraMatchHint',
  'identitySources.preflight.oidc.entraRedirect',
  'identitySources.preflight.oidc.entraGroupsClaim',
]

const detailView = (issuer, overrides = {}) => ({
  name: 'corp',
  issuer,
  client_id: 'cid',
  scopes: 'openid profile email',
  groups_claim: '',
  admission_mode: 'jit_with_rules',
  admission_rules: '{"tid":["t-1"]}',
  has_secret: true,
  enabled: true,
  redirect_uri: 'https://bastion.example.com/api/v1/auth/oidc/callback',
  redirect_uri_state: 'ready',
  ...overrides,
})

const mountPage = () =>
  mount(OIDCSourceDetail, {
    global: {
      plugins: [ElementPlus],
      stubs: { 'router-link': { template: '<a><slot /></a>' } },
    },
  })

// el-input 把非 class／style 的屬性交給內層 input；兩種落點都認
const groupsClaimInput = (wrapper) => {
  const el = wrapper.find('[data-test="groups-claim-input"]')
  return el.element.tagName === 'INPUT' ? el : el.find('input')
}

describe('OIDCSourceDetail：Entra 來源的設定引導', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    route.params = {}
  })

  it('Entra issuer 時各欄顯示在 Entra 的取得位置', async () => {
    route.params = { id: '5' }
    getDetailMock.mockResolvedValue(detailView(ENTRA_ISSUER))
    const wrapper = mountPage()
    await flushPromises()

    const text = wrapper.text()
    for (const key of ENTRA_FIELD_KEYS) {
      expect(text, key).toContain(t(key))
    }
  })

  it('非 Entra issuer 時不顯示任何 Entra 提示', async () => {
    route.params = { id: '6' }
    getDetailMock.mockResolvedValue(detailView(OTHER_ISSUER))
    const wrapper = mountPage()
    await flushPromises()

    const text = wrapper.text()
    for (const key of ENTRA_FIELD_KEYS) {
      expect(text, key).not.toContain(t(key))
    }
  })

  it('Entra 下輸入群組宣告名不自動勾 groups 範圍', async () => {
    const wrapper = mountPage()
    await flushPromises()
    wrapper.vm.form.issuer = ENTRA_ISSUER
    await flushPromises()

    await groupsClaimInput(wrapper).setValue('groups')
    await flushPromises()

    expect(wrapper.vm.form.groups_claim).toBe('groups')
    expect(wrapper.vm.form.scopeExtras).not.toContain('groups')
    // 缺範圍的一般警告不適用於 Entra
    expect(wrapper.text()).not.toContain(t('identitySources.oidc.groupsScopeMissingHint'))
  })

  it('非 Entra 下輸入群組宣告名仍自動勾 groups 範圍', async () => {
    const wrapper = mountPage()
    await flushPromises()
    wrapper.vm.form.issuer = OTHER_ISSUER
    await flushPromises()

    await groupsClaimInput(wrapper).setValue('groups')
    await flushPromises()

    expect(wrapper.vm.form.scopeExtras).toContain('groups')
    expect(wrapper.text()).toContain(t('identitySources.oidc.groupsScopeAutoAdded'))
  })

  it('Entra 且範圍含 groups 時顯示登入會被拒的警告；非 Entra 不顯示', async () => {
    route.params = { id: '7' }
    getDetailMock.mockResolvedValue(
      detailView(ENTRA_ISSUER, { scopes: 'openid profile email groups', groups_claim: 'groups' })
    )
    const wrapper = mountPage()
    await flushPromises()

    const warning = wrapper.find('[data-test="entra-groups-scope-warning"]')
    expect(warning.exists()).toBe(true)
    expect(warning.text()).toBe(t('identitySources.oidc.entra.groupsScopeRejected'))
    // 載入既有設定時不悄悄改授權範圍
    expect(wrapper.vm.form.scopeExtras).toContain('groups')

    wrapper.vm.form.issuer = OTHER_ISSUER
    await flushPromises()
    expect(wrapper.find('[data-test="entra-groups-scope-warning"]').exists()).toBe(false)
  })

  it('通用的 groups 範圍提示只在非 Entra 來源顯示', async () => {
    route.params = { id: '8' }
    getDetailMock.mockResolvedValue(detailView(ENTRA_ISSUER))
    const wrapper = mountPage()
    await flushPromises()

    const hint = t('identitySources.oidc.groupsScopeHint')
    expect(wrapper.find('[data-test="groups-scope-hint"]').exists()).toBe(false)
    expect(wrapper.text()).not.toContain(hint)

    wrapper.vm.form.issuer = OTHER_ISSUER
    await flushPromises()
    const shown = wrapper.find('[data-test="groups-scope-hint"]')
    expect(shown.exists()).toBe(true)
    expect(shown.text()).toBe(hint)
  })

  it('群組宣告名欄沒有看似已填值的預設字樣', async () => {
    const wrapper = mountPage()
    await flushPromises()

    expect(groupsClaimInput(wrapper).attributes('placeholder')).toBeUndefined()
  })
})
