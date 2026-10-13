import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import i18n from '@/i18n'
import OIDCSourceDetail from '../OIDCSourceDetail.vue'
import PreflightPanel from '../components/PreflightPanel.vue'
import { createOIDCProvider, updateOIDCProvider } from '@/api/oidc'
import { forceSharedPatch } from '@/utils/oidcProvider'

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
const getIdentitySourcesMock = vi.fn()
vi.mock('@/api/identitySources', () => ({
  getOIDCProviderDetail: (...a) => getDetailMock(...a),
  previewOIDCDiscovery: vi.fn(() => new Promise(() => {})),
  isNotImplemented: () => false,
  getSourceStatus: vi.fn(() => Promise.resolve({})),
  errorCode: () => '',
  CODE_LDAP_DIRECTORY_NOT_FOUND: 'LDAP_DIRECTORY_NOT_FOUND',
  getIdentitySources: (...a) => getIdentitySourcesMock(...a),
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

// 提供者選擇器：Entra 提示與群組引導依選擇器而非 issuer
const chooseProvider = async (wrapper, provider) => {
  await wrapper.find(`[data-test="provider-option-${provider}"]`).trigger('click')
  await flushPromises()
}

// el-input 把非 class／style 的屬性交給內層 input；兩種落點都認
const groupsClaimInput = (wrapper) => {
  const el = wrapper.find('[data-test="groups-claim-input"]')
  return el.element.tagName === 'INPUT' ? el : el.find('input')
}

describe('OIDCSourceDetail：Entra 來源的設定引導', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    route.params = {}
    getIdentitySourcesMock.mockResolvedValue({ data: [] })
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
    await chooseProvider(wrapper, 'entra')

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

    await chooseProvider(wrapper, 'other')
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

    await chooseProvider(wrapper, 'other')
    const shown = wrapper.find('[data-test="groups-scope-hint"]')
    expect(shown.exists()).toBe(true)
    expect(shown.text()).toBe(hint)
  })

  it('群組宣告名欄沒有看似已填值的預設字樣', async () => {
    const wrapper = mountPage()
    await flushPromises()

    expect(groupsClaimInput(wrapper).attributes('placeholder')).toBeUndefined()
  })

  it('群組映射區段只有宣告名欄、規則數摘要與入口按鈕，沒有規則清單與新增操作', async () => {
    route.params = { id: '5' }
    getDetailMock.mockResolvedValue(detailView(ENTRA_ISSUER, { groups_claim: 'groups' }))
    getIdentitySourcesMock.mockResolvedValue({
      data: [{ type: 'oidc', id: 5, role_mapping_rule_count: 1, user_group_mapping_rule_count: 4 }],
    })
    const wrapper = mountPage()
    await flushPromises()

    const sections = wrapper.findAll('section.source-section')
      .filter((s) => s.find('[data-test="groups-claim-input"]').exists())
    expect(sections.length).toBe(1)
    const section = sections[0]

    expect(section.findAll('[data-test="groups-claim-input"]').length).toBe(1)
    const summaries = section.findAll('[data-test="mapping-summary"]')
    expect(summaries.length).toBe(1)
    expect(summaries[0].text()).toBe(
      i18n.global.t('identitySources.mapping.summary', { roles: 1, userGroups: 4 })
    )
    const buttons = section.findAll('button.el-button')
    expect(buttons.length).toBe(1)
    expect(buttons[0].text()).toBe(t('identitySources.mapping.manage'))

    // 舊內嵌清單的痕跡：角色篩選、表格、行內新增
    expect(wrapper.find('[data-test="mapping-role-filter"]').exists()).toBe(false)
    expect(section.find('.el-table').exists()).toBe(false)
    expect(section.text()).not.toContain('新增規則')
    expect(section.text()).not.toContain('Add rule')
  })
})

// 新增與儲存：填好必填欄後直接呼叫儲存，取出送出的請求本文
const fillRequired = (wrapper, issuer = ENTRA_ISSUER) => {
  wrapper.vm.form.name = 'corp'
  wrapper.vm.form.issuer = issuer
  wrapper.vm.form.client_id = 'cid'
}

const mountEdit = async (issuer, source, kind = 'shared') => {
  route.params = { id: '11' }
  getDetailMock.mockResolvedValue(
    detailView(issuer, {
      admission_mode: 'prebound_only',
      admission_rules: '{}',
      enabled: false,
      issuer_kind: kind,
      issuer_kind_source: source,
    })
  )
  const wrapper = mountPage()
  await flushPromises()
  return wrapper
}

const switchInput = (wrapper) => wrapper.find('[data-test="force-shared-switch"]')

describe('OIDCSourceDetail：收緊開關只在切換時送出', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    route.params = {}
    getIdentitySourcesMock.mockResolvedValue({ data: [] })
    createOIDCProvider.mockResolvedValue({ data: { id: 21 } })
    updateOIDCProvider.mockResolvedValue({ data: { id: 11 } })
  })

  it('(a) 新增頁不碰開關送出：建立請求不含 force_shared 鍵', async () => {
    const wrapper = mountPage()
    await flushPromises()
    fillRequired(wrapper)
    await wrapper.vm.handleSave(true)
    await flushPromises()

    expect(createOIDCProvider).toHaveBeenCalledTimes(1)
    expect(createOIDCProvider.mock.calls[0][0]).not.toHaveProperty('force_shared')
  })

  it('(b) 編輯判定為未宣告的來源只改名稱：更新請求不含 force_shared 鍵', async () => {
    const wrapper = await mountEdit(ENTRA_ISSUER, 'unknown_default')
    wrapper.vm.form.name = 'renamed'
    await wrapper.vm.handleSave(true)
    await flushPromises()

    expect(updateOIDCProvider).toHaveBeenCalledTimes(1)
    const payload = updateOIDCProvider.mock.calls[0][1]
    expect(payload.name).toBe('renamed')
    expect(payload).not.toHaveProperty('force_shared')
  })

  it('(c) 編輯已收緊的來源並關閉開關：送 force_shared:false', async () => {
    const wrapper = await mountEdit(ENTRA_ISSUER, 'admin_forced')
    expect(wrapper.vm.form.force_shared).toBe(true)
    await switchInput(wrapper).trigger('click')
    await flushPromises()
    expect(wrapper.vm.form.force_shared).toBe(false)

    await wrapper.vm.handleSave(true)
    await flushPromises()
    expect(updateOIDCProvider.mock.calls[0][1].force_shared).toBe(false)
  })

  it('(d) 編輯部署已宣告專屬的來源並開啟開關：送 force_shared:true', async () => {
    const wrapper = await mountEdit(OTHER_ISSUER, 'deploy_declared', 'dedicated')
    expect(wrapper.vm.form.force_shared).toBe(false)
    await switchInput(wrapper).trigger('click')
    await flushPromises()

    await wrapper.vm.handleSave(true)
    await flushPromises()
    expect(updateOIDCProvider.mock.calls[0][1].force_shared).toBe(true)
  })

  it('(e) forceSharedPatch 四種組合：只有值不同於基準時才帶', () => {
    expect(forceSharedPatch(false, false)).toEqual({})
    expect(forceSharedPatch(true, true)).toEqual({})
    expect(forceSharedPatch(true, false)).toEqual({ force_shared: false })
    expect(forceSharedPatch(false, true)).toEqual({ force_shared: true })
  })
})

describe('OIDCSourceDetail：系統判定段與收緊開關的出現時機', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    route.params = {}
    getIdentitySourcesMock.mockResolvedValue({ data: [] })
  })

  const CASES = [
    { source: 'unknown_default', kind: 'shared', issuer: OTHER_ISSUER, toggle: null },
    { source: 'builtin_list', kind: 'shared', issuer: 'https://accounts.google.com', toggle: null },
    { source: 'deploy_declared', kind: 'dedicated', issuer: OTHER_ISSUER, toggle: false },
    { source: 'admin_forced', kind: 'shared', issuer: OTHER_ISSUER, toggle: true },
  ]

  for (const c of CASES) {
    it(`判定來源 ${c.source}：顯示對應判定與原因，開關${c.toggle === null ? '不出現' : c.toggle ? '出現且為開' : '出現且為關'}`, async () => {
      const wrapper = await mountEdit(c.issuer, c.source, c.kind)

      const verdict = wrapper.find('[data-test="issuer-verdict"]')
      expect(verdict.exists()).toBe(true)
      expect(verdict.find('[data-test="verdict-kind"]').text()).toBe(t(`oidcProviders.issuerKind.${c.kind}`))
      expect(verdict.find('[data-test="verdict-reason"]').text()).toBe(t(`identitySources.oidc.verdict.plain.${c.source}`))
      expect(wrapper.find('[data-test="verdict-new-hint"]').exists()).toBe(false)

      const item = wrapper.find('[data-test="force-shared-item"]')
      if (c.toggle === null) {
        expect(item.exists()).toBe(false)
      } else {
        expect(item.exists()).toBe(true)
        expect(switchInput(wrapper).classes('is-checked')).toBe(c.toggle)
        expect(switchInput(wrapper).classes('is-disabled')).toBe(false)
      }
      // 舊的欄位說明把租戶端點舉為專屬的例子，與實際判定相反，不得再出現
      expect(wrapper.text()).not.toContain(t('oidcProviders.issuerKindColumnTooltip'))
    })
  }

  it('Entra＋未宣告顯示補充句；其他提供者或其他來源不顯示', async () => {
    const note = '[data-test="verdict-entra-note"]'
    let wrapper = await mountEdit(ENTRA_ISSUER, 'unknown_default')
    expect(wrapper.find(note).exists()).toBe(true)
    expect(wrapper.find(note).text()).toBe(t('identitySources.oidc.verdict.entraNote'))

    await chooseProvider(wrapper, 'other')
    expect(wrapper.find(note).exists()).toBe(false)
    wrapper.unmount()

    wrapper = await mountEdit(ENTRA_ISSUER, 'admin_forced')
    expect(wrapper.find(note).exists()).toBe(false)
  })

  it('新增頁：無判定段、無開關，顯示「儲存後會顯示系統判定」', async () => {
    const wrapper = mountPage()
    await flushPromises()

    expect(wrapper.find('[data-test="issuer-verdict"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="force-shared-item"]').exists()).toBe(false)
    const hint = wrapper.find('[data-test="verdict-new-hint"]')
    expect(hint.exists()).toBe(true)
    expect(hint.text()).toBe(t('identitySources.oidc.verdict.newHint'))
  })
})

describe('OIDCSourceDetail：Entra 判斷依提供者選擇器', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    route.params = {}
    getIdentitySourcesMock.mockResolvedValue({ data: [] })
  })

  it('選擇器為其他 OIDC 而 issuer 是 Entra 網址：不顯示 Entra 提示', async () => {
    const wrapper = mountPage()
    await flushPromises()
    wrapper.vm.form.issuer = ENTRA_ISSUER
    wrapper.vm.form.admission_mode = 'jit_with_rules'
    await wrapper.find('[data-test="provider-guide-toggle"]').trigger('click')
    await flushPromises()

    expect(wrapper.vm.provider).toBe('other')
    const text = wrapper.text()
    for (const key of ENTRA_FIELD_KEYS) {
      expect(text, key).not.toContain(t(key))
    }
    // 面板不再依提供者分支：Entra 的取值說明只在左側
    expect(wrapper.findComponent(PreflightPanel).props()).not.toHaveProperty('entra')
  })

  it('選 Entra 而 issuer 空白：選擇器為 Entra、左側顯示 Entra 說明，接通前確認不收 entra', async () => {
    const wrapper = mountPage()
    await flushPromises()
    await chooseProvider(wrapper, 'entra')
    wrapper.vm.form.admission_mode = 'jit_with_rules'
    await flushPromises()

    expect(wrapper.vm.form.issuer).toBe('')
    expect(wrapper.vm.provider).toBe('entra')
    expect(wrapper.find('[data-test="provider-option-entra"]').classes()).toContain('is-active')
    expect(wrapper.findComponent(PreflightPanel).props()).not.toHaveProperty('entra')
    expect(wrapper.findComponent(PreflightPanel).find('[data-test="preflight-entra-hint"]').exists()).toBe(false)
    // 取值說明開著時以說明面板呈現，欄位下方不重複
    expect(wrapper.find('[data-test="provider-guide"]').text()).toContain(t('identitySources.oidc.guide.entra.issuer'))
    expect(wrapper.text()).not.toContain(t('identitySources.oidc.entra.issuer'))

    // 收合說明後，各欄改顯示 Entra 提示
    await wrapper.find('[data-test="provider-guide-toggle"]').trigger('click')
    await flushPromises()
    const text = wrapper.text()
    for (const key of ENTRA_FIELD_KEYS) {
      expect(text, key).toContain(t(key))
    }
  })
})

describe('OIDCSourceDetail：Google 的群組引導', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    route.params = {}
    getIdentitySourcesMock.mockResolvedValue({ data: [] })
  })

  it('Google＋填群組宣告名：不自動勾 groups、不顯示自動勾選通知與缺範圍提示，顯示 Google 說明', async () => {
    const wrapper = mountPage()
    await flushPromises()
    await chooseProvider(wrapper, 'google')

    // 欄位在 Google 下停用；以程式填值模擬既有設定或貼上
    expect(groupsClaimInput(wrapper).attributes('disabled')).toBeDefined()
    wrapper.vm.form.groups_claim = 'groups'
    await flushPromises()

    expect(wrapper.vm.form.scopeExtras).not.toContain('groups')
    const text = wrapper.text()
    expect(text).not.toContain(t('identitySources.oidc.groupsScopeAutoAdded'))
    expect(text).not.toContain(t('identitySources.oidc.groupsScopeMissingHint'))
    expect(wrapper.find('[data-test="google-groups-note"]').text()).toBe(t('identitySources.oidc.google.groupsClaimNote'))
  })

  it('其他 OIDC＋填群組宣告名：照舊自動勾選並顯示通知', async () => {
    const wrapper = mountPage()
    await flushPromises()
    await chooseProvider(wrapper, 'other')

    await groupsClaimInput(wrapper).setValue('groups')
    await flushPromises()

    expect(wrapper.vm.form.scopeExtras).toContain('groups')
    expect(wrapper.text()).toContain(t('identitySources.oidc.groupsScopeAutoAdded'))
    expect(wrapper.find('[data-test="google-groups-note"]').exists()).toBe(false)
  })
})
