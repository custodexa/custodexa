import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import UserPermissionOverviewTab from '../components/UserPermissionOverviewTab.vue'
import i18n, { t } from '@/i18n'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'
import { formatDateTime } from '@/utils/format'

// 權限一覽分頁：以 mock 回應驅動，驗證呈現與「不在前端計算」的邊界。
enableAutoUnmount(afterEach)
class ObserverStub { observe() {} disconnect() {} takeRecords() { return [] } }
vi.stubGlobal('MutationObserver', ObserverStub)

const h = vi.hoisted(() => ({
  overview: vi.fn(),
  probe: vi.fn(),
  assets: vi.fn(),
  roleDefs: vi.fn(),
}))

vi.mock('@/api/permissionOverview', () => ({
  getPermissionOverview: (...a) => h.overview(...a),
  probePermissionAsset: (...a) => h.probe(...a),
  PROBE_NOT_FOUND: 'NOTFOUND_ASSET',
}))
vi.mock('@/api/assets', () => ({ getAssetList: (...a) => h.assets(...a) }))
vi.mock('@/api/roleDefinitions', () => ({ listRoleDefinitions: (...a) => h.roleDefs(...a) }))

const RouterLinkStub = { props: ['to'], template: '<a :data-to="typeof to === \'string\' ? to : JSON.stringify(to)"><slot /></a>' }
const mountTab = async () => {
  const w = mount(UserPermissionOverviewTab, {
    props: { userId: 9 },
    global: { plugins: [ElementPlus], stubs: { RouterLink: RouterLinkStub, 'router-link': RouterLinkStub } },
  })
  await flushPromises()
  return w
}

const scope = (kind = 'global', paths = [], inactive = 0) => ({
  kind, nodes: paths.map((path, i) => ({ id: 100 + i, path })), inactive_node_count: inactive,
})
const src = (ref, kind, role, sc, extra = {}) => ({
  source_ref: ref, kind, role, scope: sc, effective_permissions: [], ineffective: [], ...extra,
})
const entries = (o = {}) => ({ manage: [], partial: [], read: [], available: [], ...o })
const ROLE_A = { id: 3, name: 'asset_ops', builtin_key: null }
const ROLE_USER = { id: 1, name: 'user', builtin_key: 'user' }

const overview = (over = {}) => ({
  user_id: 9,
  username: 'target',
  management: {
    identity: { super_admin: false, auditor: false, approver: false, agent: false, compat_default: false },
    sources: [src('src-1', 'direct', ROLE_A, scope('nodes', ['SIT / ELK']), { effective_permissions: ['asset:update', 'asset:view'] })],
    bindings: [{ role: ROLE_A, source_refs: ['src-1'], entries: entries({ manage: ['assets'], partial: ['users'], read: ['audit_logs'], available: ['sessions'] }), manageable_asset_count: 12 }],
    permissions: [],
    ineffective_sources: [],
  },
  connection: { available: true, items: [], manage_only: [] },
  ...over,
})

const connItem = (over = {}) => ({
  kind: 'authorization', permission: 'connect', visible_asset_count: 4, managed_asset_count: 0,
  authorization_id: 4711, target: { type: 'node', name: 'Prod / DB' }, via: { type: 'self' },
  account_scope: null, validity: { date_start: null, date_expired: null }, access_policy: 'open', ...over,
})

const load = async (body, caps = ['user:manage', 'asset:view', 'authorization:manage', 'approverscope:manage']) => {
  setCapabilitiesForTests(caps)
  h.overview.mockResolvedValue(body)
  return mountTab()
}

beforeEach(() => {
  vi.clearAllMocks()
  resetCapabilities()
  i18n.global.locale.value = 'zh-TW'
  h.assets.mockResolvedValue({ data: [{ id: 5, name: 'db-prod-01' }], total: 1 })
  h.roleDefs.mockResolvedValue({ data: [] })
})

describe('權限一覽：能管理什麼', () => {
  it('卡片數等於 bindings 數；全系統、節點路徑與台數、失效節點各自呈現', async () => {
    const body = overview()
    body.management.sources = [
      src('src-1', 'direct', ROLE_A, scope('nodes', ['SIT / ELK'], 2)),
      src('src-2', 'direct', { id: 4, name: 'ops_all', builtin_key: null }, scope('global')),
    ]
    body.management.bindings = [
      { role: ROLE_A, source_refs: ['src-1'], entries: entries({ manage: ['assets'] }), manageable_asset_count: 12 },
      { role: { id: 4, name: 'ops_all', builtin_key: null }, source_refs: ['src-2'], entries: entries({ read: ['users'] }), manageable_asset_count: null },
    ]
    h.roleDefs.mockResolvedValue({ data: [{ id: 3, scopable: true, node_range_no_effect: false }, { id: 4, scopable: true, node_range_no_effect: false }] })
    const w = await load(body)
    const cards = w.findAll('[data-test="po-card"]')
    expect(cards).toHaveLength(2)
    expect(cards[0].find('[data-test="po-card-scope"]').text()).toContain('SIT / ELK')
    expect(cards[0].find('[data-test="po-card-scope"]').text()).toContain(t('permissionOverview.card.assetCount', { n: 12 }))
    expect(cards[0].find('[data-test="po-card-inactive"]').text()).toBe(t('permissionOverview.card.inactiveNodes', { n: 2 }))
    expect(cards[1].find('[data-test="po-card-scope"]').text()).toContain(t('permissionOverview.card.global'))
    expect(cards[1].find('[data-test="po-card-scope"]').text()).not.toContain(t('permissionOverview.card.assetCount', { n: 0 }))
  })

  it('不能限定節點的角色與沒有角色的合成來源，全系統範圍寫「不適用」；超管仍寫全系統', async () => {
    h.roleDefs.mockResolvedValue({ data: [{ id: 1, scopable: true, node_range_no_effect: true, builtin_key: 'user' }] })
    const body = overview()
    body.management.sources = [src('src-1', 'direct', ROLE_USER, scope('global')), src('src-2', 'compat_default', null, scope('global'))]
    body.management.bindings = [
      { role: ROLE_USER, source_refs: ['src-1'], entries: entries(), manageable_asset_count: null },
      { role: null, source_refs: ['src-2'], entries: entries(), manageable_asset_count: null },
    ]
    let w = await load(body)
    const scopes = w.findAll('[data-test="po-card-scope"]').map((e) => e.text())
    expect(scopes[0]).toContain(t('permissionOverview.card.notApplicable'))
    expect(scopes[1]).toContain(t('permissionOverview.card.notApplicable'))

    body.management.identity.super_admin = true
    w = await load(body)
    expect(w.findAll('[data-test="po-card-scope"]')[0].text()).toContain(t('permissionOverview.card.global'))
  })

  it('入口依管理、部分管理、唯讀、可用四組列出，部分管理沿用既有鍵；沒有入口寫一句說明', async () => {
    const body = overview()
    const w = await load(body)
    const card = w.get('[data-test="po-card"]')
    expect(card.get('[data-test="po-entries-manage"]').text()).toBe(t('roles.summary.manage'))
    expect(card.get('[data-test="po-entries-partial"]').text()).toBe(t('roles.summary.partial'))
    expect(card.get('[data-test="po-entries-read"]').text()).toBe(t('roles.summary.read'))
    expect(card.get('[data-test="po-entries-available"]').text()).toBe(t('roles.summary.available'))
    expect(card.text()).toContain(t('roles.editor.entry.assets'))
    expect(card.text()).toContain(t('roles.editor.entry.sessions'))

    body.management.bindings[0].entries = entries()
    const w2 = await load(body)
    expect(w2.find('[data-test="po-card-no-entries"]').exists()).toBe(true)
  })

  it('「為什麼」只在展開後出現；直接指派只寫「管理者指派」，不含人名、日期或釘住', async () => {
    const w = await load(overview())
    expect(w.find('[data-test="po-why"]').exists()).toBe(false)
    await w.get('[data-test="po-why-toggle"]').trigger('click')
    const why = w.get('[data-test="po-why"]')
    expect(why.findAll('li')).toHaveLength(1)
    expect(why.text()).toContain(t('permissionOverview.source.direct'))
    expect(why.text()).not.toMatch(/釘住|pinned|20\d\d-\d\d-\d\d/)
    expect(t('permissionOverview.source.direct')).toBe('管理者指派')
  })

  it('同一角色有 direct 與 mapped 兩個來源時展開列出兩句；群組來源帶成員來源說明', async () => {
    const body = overview()
    body.management.sources = [
      src('src-1', 'direct', ROLE_A, scope('nodes', ['SIT / ELK'])),
      src('src-2', 'mapped', ROLE_A, scope('nodes', ['SIT / ELK']), { mapping_rules: [{ rule_id: 7, source_name: '公司 AD', external_group: 'ops-team' }] }),
      src('src-3', 'group', ROLE_A, scope('nodes', ['Prod']), { group: { id: 2, name: '維運組', member_source: 'mapped', mapping_rules: [] } }),
    ]
    body.management.bindings[0].source_refs = ['src-1', 'src-2', 'src-3']
    const w = await load(body)
    await w.get('[data-test="po-why-toggle"]').trigger('click')
    const lines = w.get('[data-test="po-why"]').findAll('li').map((l) => l.text())
    expect(lines).toHaveLength(3)
    expect(lines[0]).toContain('管理者指派')
    expect(lines[1]).toContain(t('permissionOverview.source.mapped', { source: '公司 AD', group: 'ops-team' }))
    expect(lines[2]).toContain(t('permissionOverview.source.group', { group: '維運組' }))
    expect(lines[2]).toContain(t('permissionOverview.source.groupMapped'))
  })

  it('ineffective 非空才出現未生效小節，三個原因各顯示對應說明；權限鍵不在第一層', async () => {
    const plain = await load(overview())
    expect(plain.find('[data-test="po-ineffective"]').exists()).toBe(false)
    expect(plain.find('[data-test="po-ineffective-sources"]').exists()).toBe(false)

    const body = overview()
    body.management.sources[0].ineffective = [
      { permission: 'user:manage', reason: 'permission_not_node_scopable' },
      { permission: 'role:view', reason: 'builtin_requires_global' },
    ]
    body.management.ineffective_sources = [
      { ...src('src-9', 'direct', { id: 8, name: 'gone_nodes', builtin_key: null }, scope('nodes', [], 1)), reason: 'nodes_all_deleted' },
    ]
    const w = await load(body)
    const first = w.get('[data-test="po-ineffective"]').text()
    expect(first).toContain(t('permissionOverview.ineffective.reason.permission_not_node_scopable'))
    expect(first).toContain(t('permissionOverview.ineffective.reason.builtin_requires_global'))
    expect(first).not.toContain('user:manage')
    expect(w.get('[data-test="po-ineffective-sources"]').text()).toContain(t('permissionOverview.ineffective.reason.nodes_all_deleted'))
  })

  it('細分動作在第二層：展開後列出動作名，名稱取自入口描述的鍵', async () => {
    const w = await load(overview())
    expect(w.text()).not.toContain(t('roles.editor.detail.asset.update'))
    await w.get('[data-test="po-detail-toggle"]').trigger('click')
    const detail = w.get('[data-test="po-detail"]').text()
    expect(detail).toContain(t('roles.editor.detail.asset.update'))
    expect(detail).toContain(t('roles.editor.detail.asset.view'))
  })
})

describe('權限一覽：能連線到哪裡', () => {
  const withItems = (items, extra = {}) => overview({ connection: { available: true, items, manage_only: [], ...extra } })

  it('也能管理：全部、部分、沒有三種；有任一也能管理時才出現位址通知提示', async () => {
    const w = await load(withItems([
      connItem({ visible_asset_count: 4, managed_asset_count: 4 }),
      connItem({ target: { type: 'node', name: 'Dev' }, visible_asset_count: 5, managed_asset_count: 2 }),
      connItem({ target: { type: 'node', name: 'QA' }, visible_asset_count: 3, managed_asset_count: 0 }),
    ]))
    const items = w.findAll('[data-test="po-item"]')
    expect(items).toHaveLength(3)
    expect(items[0].get('[data-test="po-item-also-manage"]').text()).toBe(t('permissionOverview.connect.alsoManage'))
    expect(items[1].get('[data-test="po-item-also-manage"]').text()).toBe(t('permissionOverview.connect.alsoManagePartial', { n: 2 }))
    expect(items[2].find('[data-test="po-item-also-manage"]').exists()).toBe(false)
    expect(items[0].find('[data-test="po-item-address-notice"]').exists()).toBe(true)
    expect(items[1].find('[data-test="po-item-address-notice"]').exists()).toBe(true)
    expect(items[2].find('[data-test="po-item-address-notice"]').exists()).toBe(false)

    const none = await load(withItems([connItem()]))
    expect(none.find('[data-test="po-item-address-notice"]').exists()).toBe(false)
  })

  it('等級標籤、時效與連線政策：open 不顯示、mixed 顯示依資產而異', async () => {
    const w = await load(withItems([
      connItem({ permission: 'view', validity: { date_start: null, date_expired: '2026-12-31T00:00:00Z' } }),
      connItem({ target: { type: 'node', name: 'Dev' }, access_policy: 'mixed', via: { type: 'group', group_name: '維運組' } }),
      connItem({ target: { type: 'node', name: 'QA' }, access_policy: 'approval' }),
    ]))
    const items = w.findAll('[data-test="po-item"]')
    expect(items[0].get('[data-test="po-item-level"]').text()).toBe(t('permissionOverview.connect.level.view'))
    expect(items[0].find('[data-test="po-item-policy"]').exists()).toBe(false)
    expect(items[0].text()).toContain(t('permissionOverview.connect.validity.until', { date: formatDateTime('2026-12-31T00:00:00Z') }))
    expect(items[1].get('[data-test="po-item-policy"]').text()).toBe(t('permissionOverview.connect.policy.mixed'))
    expect(items[1].text()).toContain(t('permissionOverview.connect.via.group', { group: '維運組' }))
    expect(items[2].get('[data-test="po-item-policy"]').text()).toBe(t('permissionOverview.connect.policy.approval'))
    expect(items[0].text()).toContain('Prod / DB')
  })

  it('「為什麼」展開：授權主體、帳號範圍與時效；看不到的授權記錄只給等級與台數', async () => {
    const w = await load(withItems([
      connItem({ account_scope: ['root', 'deploy'] }),
      { kind: 'undisclosed_authorization', permission: 'connect', visible_asset_count: 3, managed_asset_count: 0 },
      { kind: 'approver_scope', permission: 'view', visible_asset_count: 6, managed_asset_count: 0 },
    ]))
    const items = w.findAll('[data-test="po-item"]')
    expect(items[0].find('[data-test="po-item-why"]').exists()).toBe(false)
    await items[0].get('[data-test="po-item-why-toggle"]').trigger('click')
    const why = items[0].get('[data-test="po-item-why"]').text()
    expect(why).toContain(t('permissionOverview.connect.via.self'))
    expect(why).toContain(t('permissionOverview.connect.account.named', { accounts: 'root、deploy' }))
    expect(why).toContain(t('permissionOverview.connect.validity.permanent'))
    expect(items[1].text()).toContain(t('permissionOverview.connect.undisclosed', { n: 3 }))
    expect(items[1].find('[data-test="po-item-why-toggle"]').exists()).toBe(false)
    expect(items[2].text()).toContain(t('permissionOverview.connect.approverScope', { n: 6 }))
  })

  it('能管不能連每筆一行；看不到的資產只在欄位存在且大於 0 時出現', async () => {
    const body = withItems([], { out_of_scope_asset_count: 2 })
    body.connection.manage_only = [{ node_path: 'Lab / Linux', asset_count: 8 }, { node_path: 'Lab / Win', asset_count: 1 }]
    const w = await load(body)
    const rows = w.findAll('[data-test="po-manage-only"]').map((r) => r.text())
    expect(rows).toEqual([
      t('permissionOverview.connect.manageOnly', { path: 'Lab / Linux', n: 8, name: 'target' }),
      t('permissionOverview.connect.manageOnly', { path: 'Lab / Win', n: 1, name: 'target' }),
    ])
    expect(w.get('[data-test="po-out-of-scope"]').text()).toBe(t('permissionOverview.connect.outOfScope', { n: 2 }))

    for (const v of [undefined, 0]) {
      const b = withItems([], v === undefined ? {} : { out_of_scope_asset_count: v })
      const w2 = await load(b)
      expect(w2.find('[data-test="po-out-of-scope"]').exists()).toBe(false)
    }
  })

  it('out_of_scope_asset_count 只在頂層（舊錯誤形狀）時不顯示', async () => {
    const body = withItems([])
    body.out_of_scope_asset_count = 4
    const w = await load(body)
    expect(w.find('[data-test="po-out-of-scope"]').exists()).toBe(false)
  })

  it('connection.available=false 時整欄只剩無權說明', async () => {
    const w = await load(overview({ connection: { available: false } }))
    const col = w.get('[data-test="po-connect"]')
    expect(col.get('[data-test="po-connect-unavailable"]').text()).toBe(t('permissionOverview.connect.unavailable'))
    expect(col.findAll('[data-test="po-item"]')).toHaveLength(0)
    expect(col.find('[data-test="po-out-of-scope"]').exists()).toBe(false)
  })

  it('連線面沒有任何項目時顯示空狀態說明；有項目或隱含身分摘要時不顯示', async () => {
    const empty = await load(overview())
    expect(empty.get('[data-test="po-connect-empty"]').text()).toBe(t('permissionOverview.connect.empty'))
    const withRow = await load(withItems([connItem()]))
    expect(withRow.find('[data-test="po-connect-empty"]').exists()).toBe(false)
    const admin = await load(withItems([], { role_override: 'admin' }))
    expect(admin.find('[data-test="po-connect-empty"]').exists()).toBe(false)
  })
})

describe('權限一覽：查一台資產', () => {
  const pick = async (w, id = 5) => {
    w.getComponent({ name: 'ElSelect' }).vm.$emit('change', id)
    await flushPromises()
  }
  const probeBody = (over = {}) => ({
    user_id: 9, asset_id: 5,
    manage: { allowed: true, grants: [{ role: ROLE_A, scope: scope('nodes', ['SIT / ELK']) }] },
    connect: { available: true, allowed: false, items: [] },
    ...over,
  })

  it('輸入建議的資產列表請求不帶 authorized_only；選定後呼叫一次 probe 並顯示兩格', async () => {
    h.probe.mockResolvedValue(probeBody())
    const w = await load(overview())
    expect(h.assets).toHaveBeenCalled()
    for (const call of h.assets.mock.calls) expect(call[0]).not.toHaveProperty('authorized_only')
    await pick(w)
    expect(h.probe).toHaveBeenCalledTimes(1)
    expect(h.probe).toHaveBeenCalledWith(9, 5)
    expect(w.get('[data-test="po-probe-manage"]').text()).toContain(t('permissionOverview.probe.manageYes'))
    expect(w.get('[data-test="po-probe-manage"]').text()).toContain('SIT / ELK')
    expect(w.get('[data-test="po-probe-connect"]').text()).toContain(t('permissionOverview.probe.connectNo'))
  })

  it('connect.available=false 時第二格寫無法顯示能否連線', async () => {
    h.probe.mockResolvedValue(probeBody({ connect: { available: false } }))
    const w = await load(overview())
    await pick(w)
    expect(w.get('[data-test="po-probe-connect"]').text()).toBe(t('permissionOverview.probe.connectUnavailable'))
    expect(w.find('[data-test="po-probe-batch-link"]').exists()).toBe(false)
  })

  it('NOTFOUND_ASSET 顯示查無此資產且不顯示任何名稱', async () => {
    h.probe.mockRejectedValue({ response: { status: 404, data: { code: 'NOTFOUND_ASSET' } } })
    const w = await load(overview())
    await pick(w)
    expect(w.get('[data-test="po-probe-not-found"]').text()).toBe(t('permissionOverview.probe.notFound'))
    expect(w.find('[data-test="po-probe-manage"]').exists()).toBe(false)
    expect(w.get('[data-test="po-probe"]').text()).not.toContain('db-prod-01\n')
  })

  it('被檢視者是有效超管時，第二格寫不需要資產授權就能連線所有主機', async () => {
    h.probe.mockResolvedValue(probeBody({ connect: { available: true, allowed: true, role_override: 'admin' } }))
    const w = await load(overview())
    await pick(w)
    expect(w.get('[data-test="po-probe-connect"]').text()).toContain(t('permissionOverview.identity.superAdminConnect'))
  })

  it('不能連線時，檢視者能進資產授權才有前往連結', async () => {
    h.probe.mockResolvedValue(probeBody())
    let w = await load(overview())
    await pick(w)
    expect(w.get('[data-test="po-probe-batch-link"]').attributes('data-to')).toBe('/authorizations')

    w = await load(overview(), ['user:manage', 'asset:view'])
    await pick(w)
    expect(w.find('[data-test="po-probe-batch-link"]').exists()).toBe(false)
  })

  it('檢視者不具資產檢視能力時整個區塊不呈現', async () => {
    const w = await load(overview(), ['user:manage'])
    expect(w.find('[data-test="po-probe"]').exists()).toBe(false)
    expect(h.assets).not.toHaveBeenCalled()
  })
})

describe('權限一覽：特殊主體與邊界', () => {
  const ident = (o) => ({ super_admin: false, auditor: false, approver: false, agent: false, compat_default: false, ...o })

  it('五種身分各顯示對應說明句，皆非空白頁', async () => {
    const empty = { sources: [], bindings: [], permissions: [], ineffective_sources: [] }
    const sup = await load(overview({
      management: { ...empty, identity: ident({ super_admin: true }) },
      connection: { available: true, role_override: 'admin', items: [], manage_only: [] },
    }))
    expect(sup.get('[data-test="po-identity-super"]').text()).toBe(t('permissionOverview.identity.superAdmin'))
    expect(sup.get('[data-test="po-connect-admin"]').text()).toBe(t('permissionOverview.identity.superAdminConnect'))

    const aud = await load(overview({
      management: { ...empty, identity: ident({ auditor: true }) },
      connection: { available: true, role_override: 'auditor', items: [], manage_only: [] },
    }))
    expect(aud.get('[data-test="po-identity-auditor"]').text()).toBe(t('permissionOverview.identity.auditor'))
    expect(aud.get('[data-test="po-connect-auditor"]').text()).toBe(t('permissionOverview.identity.auditorConnect'))

    const apr = await load(overview({ management: { ...empty, identity: ident({ approver: true }) } }))
    expect(apr.get('[data-test="po-identity-approver"]').text()).toContain(t('permissionOverview.identity.approver'))

    const zero = overview()
    zero.management = {
      identity: ident({ compat_default: true }), permissions: [], ineffective_sources: [],
      sources: [src('src-1', 'compat_default', null, scope('global'))],
      bindings: [{ role: null, source_refs: ['src-1'], entries: entries({ available: ['sessions'] }), manageable_asset_count: null }],
    }
    const z = await load(zero)
    expect(z.get('[data-test="po-card"]').text()).toContain(t('permissionOverview.identity.compatDefault'))

    const agent = overview()
    agent.management = {
      identity: ident({ agent: true }), permissions: [], ineffective_sources: [],
      sources: [src('src-1', 'agent_fixed', null, scope('global'))],
      bindings: [{ role: null, source_refs: ['src-1'], entries: entries(), manageable_asset_count: null }],
    }
    const a = await load(agent)
    expect(a.get('[data-test="po-card"]').text()).toContain(t('permissionOverview.identity.agent'))
    for (const w of [sup, aud, apr, z, a]) expect(w.text().trim().length).toBeGreaterThan(0)
  })

  it('審核資格的審核範圍連結只在檢視者能進審核範圍頁時出現', async () => {
    const body = overview()
    body.management.identity.approver = true
    let w = await load(body)
    expect(w.get('[data-test="po-approver-link"]').attributes('data-to')).toBe('/approver-scopes')
    w = await load(body, ['user:manage', 'asset:view'])
    expect(w.find('[data-test="po-approver-link"]').exists()).toBe(false)
  })

  it('第一層文字不含權限鍵、角色內建鍵與數字識別，也不含指派者、日期或釘住', async () => {
    const body = overview()
    body.management.sources[0].ineffective = [{ permission: 'user:manage', reason: 'permission_not_node_scopable' }]
    body.management.bindings[0].role = { id: 3, name: 'asset_ops', builtin_key: 'builtin_asset_ops' }
    body.connection.items = [connItem({ managed_asset_count: 1 })]
    body.connection.manage_only = [{ node_path: 'Lab', asset_count: 3 }]
    const w = await load(body)
    const text = w.text()
    expect(text).not.toMatch(/[a-z][a-z_-]*:[a-z][a-z_-]*/i)
    expect(text).not.toContain('builtin_asset_ops')
    expect(text).not.toContain('4711')
    expect(text).not.toMatch(/#\d+|\bID\b/)
    expect(text).not.toMatch(/釘住|pinned|assigner|assigned_by/)
    expect(text).toContain(t('permissionOverview.separationNote'))
  })

  it('換成另一位使用者時重新請求新使用者的權限一覽', async () => {
    const w = await load(overview())
    expect(h.overview).toHaveBeenCalledTimes(1)
    expect(h.overview).toHaveBeenLastCalledWith(9)
    await w.setProps({ userId: 12 })
    await flushPromises()
    expect(h.overview).toHaveBeenCalledTimes(2)
    expect(h.overview).toHaveBeenLastCalledWith(12)
  })

  it('載入失敗只顯示失敗說明，不顯示空白頁', async () => {
    setCapabilitiesForTests(['user:manage', 'asset:view'])
    h.overview.mockRejectedValue(new Error('x'))
    const w = await mountTab()
    expect(w.get('[data-test="po-load-failed"]').exists()).toBe(true)
  })
})
