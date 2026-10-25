import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { computed } from 'vue'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessageBox } from 'element-plus'
import AssetPolicyTable from '@/components/AssetPolicyTable.vue'
import Authorizations from '@/views/Authorizations.vue'
import AccessControl from '@/views/AccessControl.vue'
import router from '@/router'
import { createAuthGuard } from '@/router/index'
import { resetSessionForTests, setAccessToken } from '@/utils/session'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'
import { meBody } from '@/composables/__tests__/capabilityFixtures'
import zhTW from '@/i18n/locales/zh-TW.json'
import enUS from '@/i18n/locales/en-US.json'
import jaJP from '@/i18n/locales/ja-JP.json'

// 連線政策覆寫表的範圍化呈現與兩個入口：資料來源是覆寫清單查詢（不是資產列表）、
// 範圍提示與範圍外計數只依伺服器回應、資產授權頁分頁依能力出現且切到才載入。

enableAutoUnmount(afterEach)
class ObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', ObserverStub)
vi.stubGlobal('ResizeObserver', ObserverStub)
vi.setConfig({ testTimeout: 20_000 })

const STUB_ROWS = Symbol('policyRows')
const tableStub = {
  name: 'ElTable',
  props: ['data'],
  provide() {
    return { [STUB_ROWS]: computed(() => this.data || []) }
  },
  template: '<div class="table-stub"><slot /></div>',
}
const tableColumnStub = {
  name: 'ElTableColumn',
  props: ['label', 'prop'],
  inject: { stubRows: { from: STUB_ROWS, default: null } },
  computed: {
    rows() {
      const v = this.stubRows
      if (!v) return []
      return Array.isArray(v) ? v : v.value || []
    },
  },
  template: `<div class="col-stub">
    <div v-for="(row, i) in rows" :key="i"><slot :row="row" :column="{}" :$index="i" /></div></div>`,
}
const ElSelectStub = {
  name: 'ElSelect',
  props: ['modelValue'],
  emits: ['change', 'update:modelValue'],
  template: '<div class="select-stub" :data-value="modelValue"><slot /></div>',
}
const ElOptionStub = {
  name: 'ElOption',
  props: ['label', 'value'],
  template: '<div class="option-stub">{{ label }}</div>',
}
const stubs = {
  ElTable: tableStub,
  ElTableColumn: tableColumnStub,
  'el-select': ElSelectStub,
  'el-option': ElOptionStub,
  RouterLink: { template: '<a><slot /></a>' },
}

const getOverridesMock = vi.fn()
const getAssetListMock = vi.fn()
const updateAssetMock = vi.fn()
const getAuthorizationsMock = vi.fn()
const getPoliciesMock = vi.fn()

vi.mock('@/api/assets', () => ({
  getAccessPolicyOverrides: (...a) => getOverridesMock(...a),
  getAssetList: (...a) => getAssetListMock(...a),
  updateAsset: (...a) => updateAssetMock(...a),
  getAssetGroups: vi.fn().mockResolvedValue({ data: [] }),
  getAssetTags: vi.fn().mockResolvedValue({ data: [] }),
  getAssetNodeTree: vi.fn().mockResolvedValue({ data: [] }),
}))
vi.mock('@/api/authorizations', () => ({
  getAuthorizations: (...a) => getAuthorizationsMock(...a),
  getSelfSubjects: vi.fn().mockResolvedValue({ applies: false }),
  getAuthorizationSubjectOptions: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  getAuthorizationTargetOptions: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  batchCreateAuthorizations: vi.fn(),
  deleteAuthorization: vi.fn(),
  updateAuthorizationAccounts: vi.fn(),
  getEffectiveAssets: vi.fn().mockResolvedValue({ assets: [] }),
  getEffectiveUsers: vi.fn().mockResolvedValue({ users: [] }),
}))
vi.mock('@/api/accessRequests', () => ({ revokeAccessRequest: vi.fn() }))
vi.mock('@/api/auth', () => ({
  getUsers: vi.fn().mockResolvedValue({ data: [] }),
  getCurrentUser: vi.fn(),
  logout: vi.fn(),
}))
vi.mock('@/api/userGroups', () => ({ getUserGroups: vi.fn().mockResolvedValue({ data: [] }) }))
vi.mock('@/api/assetAccounts', () => ({ listAssetAccounts: vi.fn().mockResolvedValue({ data: [] }) }))
vi.mock('@/api/securityPolicies', () => ({
  getSecurityPolicies: (...a) => getPoliciesMock(...a),
  updateSecurityPolicies: vi.fn(),
  previewCompliance: vi.fn().mockResolvedValue({ data: { draft: true, verdicts: [] } }),
  previewApplyPolicies: vi.fn(),
}))

const ACCESS_PERM = 'access_policy:manage'
const page = (rows, meta = { global_default: 'open', scoped: false }) => ({
  data: rows,
  total: rows.length,
  page: 1,
  page_size: 1000,
  meta,
})
const ROW = (over = {}) => ({
  id: 4,
  name: 'db-1',
  protocol: 'ssh',
  access_policy: 'approval',
  node_ids: [1],
  node_paths: ['機房 / A'],
  ...over,
})

beforeEach(() => {
  vi.clearAllMocks()
  resetCapabilities()
  getOverridesMock.mockResolvedValue(page([ROW()]))
  getAssetListMock.mockResolvedValue({ data: [], total: 0 })
  updateAssetMock.mockResolvedValue({})
  getAuthorizationsMock.mockResolvedValue({ data: [], total: 0 })
  getPoliciesMock.mockResolvedValue({
    data: [
      { key: 'access_policy_default', type: 'enum', enum_order: ['open', 'reason', 'approval'], label: '連線申請政策（全域預設）', value: 'open' },
    ],
    groups: [],
  })
})

const mountTable = async (props = {}) => {
  const w = mount(AssetPolicyTable, { props, global: { plugins: [ElementPlus], stubs } })
  await flushPromises()
  return w
}

describe('連線政策覆寫表的資料來源與範圍呈現', () => {
  it('掛載時呼叫覆寫清單查詢、不呼叫資產列表', async () => {
    await mountTable()
    expect(getOverridesMock).toHaveBeenCalledTimes(1)
    expect(getOverridesMock).toHaveBeenCalledWith({ overridden: true, page: 1, page_size: 1000 })
    expect(getAssetListMock).not.toHaveBeenCalled()
  })

  it('meta.scoped 為 true 才顯示範圍提示', async () => {
    getOverridesMock.mockResolvedValue(page([ROW()], { global_default: 'open', scoped: true }))
    const on = await mountTable()
    expect(on.find('[data-test="policy-scoped-hint"]').text()).toBe(zhTW.assetPolicyTable.scopedHint)

    getOverridesMock.mockResolvedValue(page([ROW()], { global_default: 'open', scoped: false }))
    const off = await mountTable()
    expect(off.find('[data-test="policy-scoped-hint"]').exists()).toBe(false)
    expect(off.text()).not.toContain(zhTW.assetPolicyTable.scopedHint)
  })

  it('提示列插值 meta.global_default 的譯名', async () => {
    getOverridesMock.mockResolvedValue(page([ROW()], { global_default: 'reason', scoped: false }))
    const w = await mountTable()
    const banner = w.find('[data-test="policy-default-banner"]').text()
    expect(banner).toBe(zhTW.assetPolicyTable.defaultBanner.replace('{policy}', zhTW.enum.accessPolicy.reason))
  })

  it('帶範圍外計數的列顯示計數，且只列範圍內節點路徑', async () => {
    getOverridesMock.mockResolvedValue(
      page([ROW({ out_of_scope_node_count: 2 }), ROW({ id: 5, name: 'db-2', out_of_scope_node_count: 0 })], {
        global_default: 'open',
        scoped: true,
      })
    )
    const w = await mountTable()
    const notes = w.findAll('[data-test="policy-out-of-scope"]')
    expect(notes).toHaveLength(1)
    expect(notes[0].text()).toBe('另有 2 個範圍外節點。')
    expect(notes[0].text()).toBe(zhTW.assets.scopedOutOfScopeNodes.replace('{n}', '2'))
    expect(w.text()).toContain('機房 / A')
    expect(w.text()).not.toContain('機房 / B')
  })

  it('未帶計數鍵的列（全域持有者）不顯示計數', async () => {
    const w = await mountTable()
    expect(w.find('[data-test="policy-out-of-scope"]').exists()).toBe(false)
  })

  it('候選資產走遠端搜尋（overridden=false），空關鍵字不查詢', async () => {
    const w = await mountTable()
    getOverridesMock.mockClear()
    const picker = w.findAllComponents({ name: 'ElSelect' })[0]
    const search = picker.vm.$attrs['remote-method'] ?? picker.vm.$attrs.remoteMethod
    await search('  ')
    expect(getOverridesMock).not.toHaveBeenCalled()
    getOverridesMock.mockResolvedValueOnce(page([ROW({ id: 9, name: 'web-1', access_policy: null })]))
    await search('web')
    await flushPromises()
    expect(getOverridesMock).toHaveBeenCalledWith({ overridden: false, search: 'web', page: 1, page_size: 50 })
    expect(w.text()).toContain('web-1（SSH）')
  })

  it('approval 改 reason 仍跳放寬確認，內文為現行放寬提示；取消不送出', async () => {
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm')
    const w = await mountTable()
    const rowSelect = () =>
      w.findAllComponents({ name: 'ElSelect' }).find((s) => s.attributes('aria-label') === 'db-1 連線政策')
    confirmSpy.mockRejectedValueOnce('cancel')
    rowSelect().vm.$emit('change', 'reason')
    await flushPromises()
    expect(confirmSpy).toHaveBeenCalledTimes(1)
    const message = confirmSpy.mock.calls[0][0]
    const text = typeof message === 'string' ? message : String(message.children)
    expect(text).toContain('這是放寬。儲存後會記入操作日誌並建立系統安全告警；是否送達取決於通知通道設定與投遞結果。')
    expect(text).toContain(zhTW.accessPolicyDowngrade.notice)
    expect(updateAssetMock).not.toHaveBeenCalled()

    confirmSpy.mockResolvedValueOnce('confirm')
    rowSelect().vm.$emit('change', 'reason')
    await flushPromises()
    expect(updateAssetMock).toHaveBeenCalledWith(4, { access_policy: 'reason' })
    confirmSpy.mockRestore()
  })
})

describe('資產授權頁的連線政策分頁', () => {
  const mountAuthz = async () => {
    const w = mount(Authorizations, { global: { plugins: [ElementPlus], stubs } })
    await flushPromises()
    return w
  }
  const tabLabels = (w) => w.findAll('.el-tabs__item').map((n) => n.text())

  it('持授權規則與存取政策權限點：看見分頁；只持授權規則：不見', async () => {
    setCapabilitiesForTests(['authorization:manage', ACCESS_PERM])
    const both = await mountAuthz()
    expect(tabLabels(both)).toContain(zhTW.authorizations.tabAccessPolicy)

    setCapabilitiesForTests(['authorization:manage'])
    const only = await mountAuthz()
    expect(tabLabels(only)).not.toContain(zhTW.authorizations.tabAccessPolicy)
  })

  it('未切到該分頁前覆寫清單查詢 0 次；切過去才載入，且批次授權按鈕不渲染', async () => {
    setCapabilitiesForTests(['authorization:manage', ACCESS_PERM])
    const w = await mountAuthz()
    expect(getOverridesMock).not.toHaveBeenCalled()
    expect(w.text()).toContain(zhTW.authorizations.batchAuthorize)

    w.vm.activeTab = 'policy'
    await flushPromises()
    expect(getOverridesMock).toHaveBeenCalledTimes(1)
    expect(w.findComponent({ name: 'AssetPolicyTable' }).exists()).toBe(true)
    expect(w.text()).not.toContain(zhTW.authorizations.batchAuthorize)

    // 重新整理依目前分頁重載覆寫清單
    const refresh = w.findAll('button').find((b) => b.text().includes(zhTW.common.refresh))
    await refresh.trigger('click')
    await flushPromises()
    expect(getOverridesMock).toHaveBeenCalledTimes(2)
  })

  it('兩個入口渲染的表格欄位標題序列相同', async () => {
    setCapabilitiesForTests(['authorization:manage', ACCESS_PERM, 'securitypolicy:manage'])
    const labelsIn = (w) =>
      w
        .findComponent({ name: 'AssetPolicyTable' })
        .findAllComponents({ name: 'ElTableColumn' })
        .map((c) => c.props('label'))
    const authz = await mountAuthz()
    authz.vm.activeTab = 'policy'
    await flushPromises()
    const fromAuthz = labelsIn(authz)

    const ac = mount(AccessControl, { global: { plugins: [ElementPlus], stubs } })
    await flushPromises()
    expect(labelsIn(ac)).toEqual(fromAuthz)
    expect(fromAuthz).toEqual([
      zhTW.common.asset,
      zhTW.common.protocol,
      zhTW.assetPolicyTable.colNodes,
      zhTW.assets.accessPolicy,
      zhTW.common.actions,
    ])
  })
})

describe('只持存取政策權限點的主體沒有畫面入口', () => {
  const guard = createAuthGuard()
  const getCurrentUser = async () => (await import('@/api/auth')).getCurrentUser

  beforeEach(() => {
    localStorage.clear()
    resetSessionForTests()
  })

  it('只持 access_policy:manage 與 asset:view：/authorizations 與 /access-control 皆導回儀表板', async () => {
    setAccessToken('t')
    ;(await getCurrentUser()).mockResolvedValue(
      meBody(['user'], {}, { permissions: [ACCESS_PERM, 'asset:view'] })
    )
    for (const path of ['/authorizations', '/access-control']) {
      const next = vi.fn()
      const resolved = router.resolve(path)
      await guard({ path, meta: resolved.meta, query: {} }, { path: '/', meta: {} }, next)
      expect(next, path).toHaveBeenLastCalledWith('/dashboard')
    }
  })
})

describe('四個新增文案鍵三語齊備', () => {
  const get = (obj, key) => key.split('.').reduce((o, k) => o?.[k], obj)
  const KEYS = [
    'authorizations.tabAccessPolicy',
    'assetPolicyTable.defaultBanner',
    'assetPolicyTable.scopedHint',
    'assetPolicyTable.colNodes',
  ]
  it('zh-TW、en-US、ja-JP 皆有非空字串，插值變數一致', () => {
    for (const key of KEYS) {
      for (const [name, loc] of [['zh-TW', zhTW], ['en-US', enUS], ['ja-JP', jaJP]]) {
        const v = get(loc, key)
        expect(typeof v, `${name} ${key}`).toBe('string')
        expect(v.length, `${name} ${key}`).toBeGreaterThan(0)
      }
    }
    for (const loc of [zhTW, enUS, jaJP]) {
      expect(get(loc, 'assetPolicyTable.defaultBanner')).toContain('{policy}')
    }
  })
})
