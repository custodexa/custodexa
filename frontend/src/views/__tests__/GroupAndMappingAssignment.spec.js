import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { reactive } from 'vue'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import UserGroupDetail from '../UserGroupDetail.vue'
import UserGroups from '../UserGroups.vue'
import GroupMembersTab from '../usergroups/components/GroupMembersTab.vue'
import GroupRolesTab from '../usergroups/components/GroupRolesTab.vue'
import ExternalGroupMappings from '../identity-sources/ExternalGroupMappings.vue'
import RoleNodePicker from '@/components/RoleNodePicker.vue'
import LDAPSourceDetail from '../identity-sources/LDAPSourceDetail.vue'
import OIDCSourceDetail from '../identity-sources/OIDCSourceDetail.vue'
import { ElDialogStub } from '@/__fixtures__/dialogStub'
import { previewDisabledMapping } from '@/__fixtures__/rolePreviews'
import i18n from '@/i18n'
import zhTW from '@/i18n/locales/zh-TW.json'
import enUS from '@/i18n/locales/en-US.json'
import jaJP from '@/i18n/locales/ja-JP.json'

enableAutoUnmount(afterEach)

const h = vi.hoisted(() => ({ request: vi.fn(), push: vi.fn(), route: null }))

// 直接攔在 HTTP 層：驗證實際送出的路徑與本文鍵集合
vi.mock('@/api/request', () => ({ default: (...a) => h.request(...a) }))
vi.mock('vue-router', () => ({
  useRoute: () => h.route,
  useRouter: () => ({ push: h.push, replace: vi.fn() }),
}))

// happy-dom 的 MutationObserver 與 el-table 不相容（同 UserGroups.spec）
vi.stubGlobal(
  'MutationObserver',
  class {
    observe() {}
    disconnect() {}
    takeRecords() {
      return []
    }
  }
)

const t = (k, p) => i18n.global.t(k, p)
const err = (status, code) => ({ response: { status, data: code ? { error: { code } } : {} } })

const defs = [
  { id: 1, name: 'auditor', assignment_state: 'open', management_class: false, group_bindable: true },
  { id: 2, name: 'approver', assignment_state: 'open', management_class: false, group_bindable: false },
  { id: 3, name: 'security_admin', assignment_state: 'protected', management_class: true, group_bindable: true },
  { id: 4, name: 'asset_admin', assignment_state: 'not_open', management_class: true, group_bindable: true },
  { id: 5, name: 'cred_admin', assignment_state: 'open', management_class: true, group_bindable: true },
]
const noOp = { marks: [], self_direction: '', routes_gained: [], routes_lost: [], evaluated: 0 }
const noHit = { total: 0, matched: 0, truncated: false, subjects: [], operation: noOp }
const hit = { ...noHit, total: 1, matched: 1, operation: { ...noOp, marks: ['management_grant'], evaluated: 1 } }

const alice = { id: 1, username: 'alice' }
const bob = { id: 2, username: 'bob' }
const mkGroup = (over = {}) => ({
  id: 1,
  name: 'SRE',
  description: '',
  users: [alice, bob],
  manual_user_ids: [1],
  mapped_user_ids: [2],
  member_sources: [
    { user_id: 1, manual: true, mapped: false },
    { user_id: 2, manual: false, mapped: true },
  ],
  ...over,
})
const rule = (n, over = {}) => ({
  rule_id: n,
  source_type: 'oidc',
  source_name: `idp${n}`,
  source_enabled: true,
  external_group_label: `grp${n}`,
  ...over,
})

let cfg
const setup = (over = {}) => {
  cfg = {
    groups: [mkGroup()],
    bindings: [{ role_id: 1, role_name: 'auditor', scope: 'global' }],
    bindingsById: {},
    mappings: { data: [rule(1)], total: 1 },
    mappingsError: null,
    preview: noHit,
    previewError: null,
    ...over,
  }
  h.request.mockImplementation(async (c) => {
    const key = `${c.method.toUpperCase()} ${c.url}`
    if (key === 'GET /role-definitions') return { data: defs, total: defs.length, can_define: false }
    if (key === 'GET /user-groups') return { data: cfg.groups, total: cfg.groups.length }
    if (key === 'GET /users') return { data: [alice, bob, { id: 3, username: 'carol' }] }
    const rb = /^GET \/user-groups\/(\d+)\/role-bindings$/.exec(key)
    if (rb) {
      const rows = cfg.bindingsById[rb[1]] || cfg.bindings
      return { data: rows, total: rows.length }
    }
    if (/^GET \/user-groups\/\d+\/external-mappings$/.test(key)) {
      if (cfg.mappingsError) throw cfg.mappingsError
      return cfg.mappings
    }
    if (key === 'POST /role-assignment-previews') {
      if (cfg.previewError) throw cfg.previewError
      return cfg.preview
    }
    if (key === 'PUT /user-groups/1/members') return { id: 1 }
    if (key === 'PUT /user-groups/1/role-bindings') return { data: [] }
    throw new Error(`unexpected request ${key}`)
  })
}
const calls = (method, url) =>
  h.request.mock.calls.map((c) => c[0]).filter((c) => c.method.toUpperCase() === method && c.url === url)

const mountDetail = async (query = {}) => {
  h.route = reactive({ params: { id: '1' }, query })
  const w = mount(UserGroupDetail, {
    global: { plugins: [ElementPlus], stubs: { ElDialog: ElDialogStub } },
  })
  await flushPromises()
  return w
}
const wait = (ms) => new Promise((r) => setTimeout(r, ms))

beforeEach(() => {
  h.request.mockReset()
  h.push.mockReset()
  i18n.global.locale.value = 'zh-TW'
  setup()
})

describe('群組詳情：成員分頁', () => {
  it('群組帶 protected 角色：成員維護停用並說明；否則開啟穿梭框', async () => {
    const open = await mountDetail()
    expect(open.find('[data-test="maintain-blocked"]').exists()).toBe(false)
    expect(open.find('[data-test="member-transfer"]').exists()).toBe(true)

    setup({ bindings: [{ role_id: 3, role_name: 'security_admin', scope: 'global' }] })
    const blocked = await mountDetail()
    expect(blocked.find('[data-test="member-transfer"]').exists()).toBe(false)
    expect(blocked.find('[data-test="members-save"]').exists()).toBe(false)
    expect(blocked.get('[data-test="maintain-blocked"]').text()).toContain('只有超級管理者能加入或移除成員')
  })

  it('成員列表標示加入方式：手動、外部群組映射', async () => {
    const w = await mountDetail()
    expect(w.get('[data-test="member-source-1"]').text()).toBe(t('identityGroupMappings.memberManual'))
    expect(w.get('[data-test="member-source-2"]').text()).toBe(t('identityGroupMappings.memberMapped'))
  })

  it('移除手動成員 A 後儲存：預覽本文鍵集合恰為三個；返回修改不送 PUT；仍要儲存送出的本文只含 manual_user_ids 且不含映射成員 B', async () => {
    setup({ preview: hit })
    const w = await mountDetail()
    w.findComponent(GroupMembersTab).vm.manualIds = []
    await flushPromises()
    await w.get('[data-test="members-save"]').trigger('click')
    await flushPromises()

    const pv = calls('POST', '/role-assignment-previews')
    expect(pv).toHaveLength(1)
    expect(Object.keys(pv[0].data).sort()).toEqual(['group_id', 'kind', 'manual_member_ids'])
    expect(pv[0].data).toMatchObject({ kind: 'group_members', group_id: 1, manual_member_ids: [] })
    expect(w.find('[data-test="danger-combo-confirm"]').exists()).toBe(true)
    expect(w.get('[data-test="danger-footnote"]').text()).toBe(t('dangerConfirm.mappedUnaffected'))

    await w.get('[data-test="danger-back"]').trigger('click')
    await flushPromises()
    expect(calls('PUT', '/user-groups/1/members')).toHaveLength(0)

    await w.get('[data-test="members-save"]').trigger('click')
    await flushPromises()
    await w.get('[data-test="danger-proceed"]').trigger('click')
    await flushPromises()
    const puts = calls('PUT', '/user-groups/1/members')
    expect(puts).toHaveLength(1)
    expect(Object.keys(puts[0].data)).toEqual(['manual_user_ids'])
    expect(puts[0].data.manual_user_ids).toEqual([])
    expect(puts[0].data.manual_user_ids).not.toContain(2)
  })

  it('預覽沒有命中時直接儲存，不開確認框', async () => {
    const w = await mountDetail()
    w.findComponent(GroupMembersTab).vm.manualIds = [1, 3]
    await flushPromises()
    await w.get('[data-test="members-save"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="danger-combo-confirm"]').exists()).toBe(false)
    expect(calls('PUT', '/user-groups/1/members')).toHaveLength(1)
  })

  it('預覽失敗：標示暫時無法取得，仍可儲存', async () => {
    setup({ previewError: err(500, 'INTERNAL') })
    const w = await mountDetail()
    w.findComponent(GroupMembersTab).vm.manualIds = []
    await flushPromises()
    await w.get('[data-test="members-save"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="danger-preview-failed"]').text()).toContain(t('dangerConfirm.previewFailed.body'))
    expect(calls('PUT', '/user-groups/1/members')).toHaveLength(0)
    await w.get('[data-test="danger-proceed"]').trigger('click')
    await flushPromises()
    expect(calls('PUT', '/user-groups/1/members')).toHaveLength(1)
  })
})

describe('群組詳情：角色與範圍分頁', () => {
  const protectedBindings = [
    { role_id: 3, role_name: 'security_admin', scope: 'global' },
    { role_id: 1, role_name: 'auditor', scope: 'global' },
  ]

  it('受保護角色卡片無移除鈕且有說明；新增另一個 open 角色後儲存，本文恰為 role_ids 且仍含保護角色', async () => {
    setup({ bindings: protectedBindings })
    const w = await mountDetail({ tab: 'roles' })
    const card = w.get('[data-test="group-role-security_admin"]')
    expect(card.find('button').exists()).toBe(false)
    expect(card.get('[data-test="protected-note"]').text()).toBe(t('userGroups.detail.roles.protectedCannotRemove'))
    expect(w.find('[data-test="remove-auditor"]').exists()).toBe(true)

    // 加入另一個 open 角色（預覽無命中，直接送出）
    w.findComponent(GroupRolesTab).vm.addPicked(5)
    await flushPromises()
    await w.get('[data-test="roles-save"]').trigger('click')
    await flushPromises()
    const puts = calls('PUT', '/user-groups/1/role-bindings')
    expect(puts).toHaveLength(1)
    expect(Object.keys(puts[0].data)).toEqual(['role_ids'])
    expect(puts[0].data.role_ids).toEqual(expect.arrayContaining([3, 1, 5]))
    const pv = calls('POST', '/role-assignment-previews').at(-1)
    expect(Object.keys(pv.data).sort()).toEqual(['group_id', 'kind', 'role_ids'])
    expect(pv.data.kind).toBe('group_roles')
  })

  it('角色卡片上方只有一句說明，不重複「群組的角色會給每一位成員」', async () => {
    const w = await mountDetail({ tab: 'roles' })
    const tab = w.get('[data-test="group-roles-tab"]')
    expect(tab.findAll('.hint')).toHaveLength(1)
    expect(tab.text().split('群組的角色會給每一位成員').length - 1).toBe(1)
  })

  it('group_bindable 為假與 protected 的角色在下拉停用', async () => {
    setup({ bindings: protectedBindings })
    const w = await mountDetail({ tab: 'roles' })
    const opts = Object.fromEntries(w.findComponent(GroupRolesTab).vm.roleOptions.map((o) => [o.name, o]))
    expect(opts.approver).toMatchObject({ disabled: true, reason: t('roles.assignState.notGroupBindable') })
    expect(opts.security_admin).toMatchObject({ disabled: true, reason: t('roles.assignState.protected') })
    expect(opts.asset_admin).toMatchObject({ disabled: true, reason: t('roles.assignState.notOpen') })
    expect(opts.cred_admin).toMatchObject({ disabled: false })
  })

  it('空群組新增管理類角色：依 operation.marks 出現會通知的確認，總數為 0 時用空群組句', async () => {
    setup({
      groups: [mkGroup({ users: [], manual_user_ids: [], mapped_user_ids: [], member_sources: [] })],
      preview: previewDisabledMapping,
    })
    const w = await mountDetail({ tab: 'roles' })
    w.findComponent(GroupRolesTab).vm.addPicked(5)
    await flushPromises()
    await w.get('[data-test="roles-save"]').trigger('click')
    await flushPromises()
    expect(calls('PUT', '/user-groups/1/role-bindings')).toHaveLength(0)
    const notify = w.get('[data-test="danger-notify"]').text()
    expect(notify).toContain(t('dangerConfirm.notify.title'))
    expect(notify).toContain(t('dangerConfirm.notify.groupEmpty', { group: 'SRE', role: 'cred_admin' }))
  })

  it('儲存後的變化：影響成員數、新增入口取自 routes_gained、連線句與使用者頁相同', async () => {
    setup({
      preview: {
        ...noHit,
        total: 3,
        subjects: [{ user_id: 1, new_combos: ['security_with_asset_or_authz'] }],
        operation: { ...noOp, routes_gained: ['/credentials'], evaluated: 3 },
      },
    })
    const w = await mountDetail({ tab: 'roles' })
    w.findComponent(GroupRolesTab).vm.addPicked(5)
    await wait(500)
    await flushPromises()
    expect(w.get('[data-test="impact-members"]').text()).toBe(t('userGroups.detail.impact.members', { n: 3 }))
    expect(w.get('[data-test="impact-routes"]').text()).toContain(t('menu.credentials'))
    expect(w.get('[data-test="impact-combo"]').text()).toBe(t('userGroups.detail.impact.comboNote', { n: 1 }))
    expect(w.get('[data-test="impact-connection"]').text()).toBe(t('userDetail.change.connectionFixed'))
  })
})

describe('群組詳情：標頭映射設定', () => {
  it('一條規則：寫出該來源與外部群組；來源停用時加註', async () => {
    const w = await mountDetail()
    expect(w.get('[data-test="mapping-sentence"]').text()).toBe(
      t('userGroups.detail.mapping.one', { source: 'idp1', group: 'grp1' })
    )
    setup({ mappings: { data: [rule(1, { source_enabled: false })], total: 1 } })
    const off = await mountDetail()
    expect(off.get('[data-test="mapping-sentence"]').text()).toContain(t('userGroups.detail.mapping.sourceDisabled'))
  })

  it('四條規則：列前三個並出現「另有 1 個群組」', async () => {
    setup({ mappings: { data: [rule(1), rule(2), rule(3), rule(4)], total: 4 } })
    const w = await mountDetail()
    const text = w.get('[data-test="mapping-sentence"]').text()
    expect(text).toContain('grp1')
    expect(text).toContain('grp3')
    expect(text).not.toContain('grp4')
    expect(text).toContain('另有 1 個群組')
  })

  it('零條規則但有映射成員：退回不指名說明，不含「尚未收回」', async () => {
    setup({ mappings: { data: [], total: 0 } })
    const w = await mountDetail()
    const text = w.get('[data-test="mapping-fallback"]').text()
    expect(text).toContain(t('userGroups.detail.mapping.fallbackTitle'))
    expect(text).not.toContain('尚未收回')
    expect(w.find('[data-test="mapping-header"]').exists()).toBe(false)
  })

  it('零條規則且沒有映射成員：不顯示映射標頭', async () => {
    setup({
      mappings: { data: [], total: 0 },
      groups: [
        mkGroup({ users: [alice], mapped_user_ids: [], member_sources: [{ user_id: 1, manual: true, mapped: false }] }),
      ],
    })
    const w = await mountDetail()
    expect(w.find('[data-test="mapping-header"]').exists()).toBe(false)
    expect(w.find('[data-test="mapping-fallback"]').exists()).toBe(false)
  })

  it('讀取映射設定失敗：退回不指名說明，頁面其餘照常', async () => {
    setup({ mappingsError: err(500, 'INTERNAL') })
    const w = await mountDetail()
    expect(w.find('[data-test="mapping-fallback"]').exists()).toBe(true)
    expect(w.find('[data-test="member-transfer"]').exists()).toBe(true)
    expect(w.find('[data-test="member-table"]').exists()).toBe(true)
  })
})

describe('群組列表', () => {
  it('群組帶 protected 角色：刪除鈕停用並有說明；其他群組不受影響；名稱連到詳情頁', async () => {
    setup({
      groups: [mkGroup(), mkGroup({ id: 2, name: 'dev', users: [], manual_user_ids: [], member_sources: [] })],
      bindingsById: { 1: [{ role_id: 3, role_name: 'security_admin', scope: 'global' }] },
    })
    const w = mount(UserGroups, { global: { plugins: [ElementPlus] } })
    await flushPromises()
    expect(w.get('[data-test="delete-1"]').attributes('disabled')).toBeDefined()
    expect(w.get('[data-test="delete-blocked-1"]').text()).toContain('只有超級管理者能刪除')
    expect(w.get('[data-test="delete-2"]').attributes('disabled')).toBeUndefined()
    expect(w.find('[data-test="delete-blocked-2"]').exists()).toBe(false)
    await w.get('[data-test="group-link-1"]').trigger('click')
    expect(h.push).toHaveBeenCalledWith('/user-groups/1?tab=roles')
  })
})

describe('文案', () => {
  it('userGroups.headerDesc 以巢狀鍵取值，三語都不含「無關」類說法', () => {
    expect(zhTW.userGroups.headerDesc).toBeTruthy()
    expect(zhTW.userGroups.headerDesc).not.toContain('無關')
    expect(enUS.userGroups.headerDesc.toLowerCase()).not.toContain('unrelated')
    expect(jaJP.userGroups.headerDesc).not.toContain('無関係')
  })
})

describe('映射頁：不選節點', () => {
  it('目標群組以節點範圍持有角色時，新增與編輯規則對話框沒有節點樹或範圍欄位，送出本文不含範圍欄位', async () => {
    setup({
      bindings: [{ role_id: 1, role_name: 'auditor', scope: 'nodes', node_ids: [11] }],
    })
    const body = (c) => c.data
    h.request.mockImplementation(async (c) => {
      const key = `${c.method.toUpperCase()} ${c.url}`
      if (key === 'GET /role-definitions') return { data: defs, total: defs.length, can_define: false }
      if (key === 'GET /user-groups') return { data: cfg.groups, total: cfg.groups.length }
      if (/^GET \/user-groups\/\d+\/role-bindings$/.test(key)) return { data: cfg.bindings, total: 1 }
      if (key === 'POST /role-assignment-previews') return noHit
      if (key === 'GET /identity-sources') return { data: [{ id: 7, type: 'oidc', name: 'demo', enabled: true }] }
      if (/user-group-usage/.test(c.url)) return { data: { asset_authorizations: 0, approver_scopes: 0, requester_scopes: 0 } }
      if (/(user-group-mappings|role-mappings|external-groups)/.test(c.url)) {
        return c.method.toUpperCase() === 'GET' ? { data: [] } : { data: { id: 11 } }
      }
      return { data: [] }
    })
    h.route = reactive({ params: { type: 'oidc', id: '7' }, query: {} })
    const w = mount(ExternalGroupMappings, {
      global: {
        plugins: [ElementPlus],
        stubs: { ElDialog: ElDialogStub, 'router-link': { template: '<a><slot /></a>' } },
      },
    })
    await flushPromises()
    w.vm.tab = 'userGroups'
    await flushPromises()
    const noRangeUi = () => {
      expect(w.findComponent(RoleNodePicker).exists()).toBe(false)
      expect(w.find('[data-test^="rnp-"]').exists()).toBe(false)
      expect(w.find('[data-test="role-node-picker"]').exists()).toBe(false)
      expect(w.find('[data-test="range-panel"]').exists()).toBe(false)
    }
    const mappingWrites = () =>
      h.request.mock.calls.map((x) => x[0]).filter((c) => /user-group-mappings/.test(c.url) && c.method.toUpperCase() !== 'GET')
    const noRangeKeys = (data) => {
      for (const k of ['role_nodes', 'node_ids', 'nodes', 'scope', 'range']) expect(data).not.toHaveProperty(k)
    }

    w.vm.openCreate()
    await flushPromises()
    w.vm.draft.match_value = 'ops'
    w.vm.draft.user_group_id = 1
    await flushPromises()
    noRangeUi()
    await w.vm.save()
    await flushPromises()
    expect(mappingWrites()).toHaveLength(1)
    expect(mappingWrites()[0].method.toUpperCase()).toBe('POST')
    noRangeKeys(body(mappingWrites()[0]))

    await w.vm.openEdit({ id: 9, match_value: 'ops', user_group_id: 1, user_group_name: 'SRE', enabled: true })
    await flushPromises()
    noRangeUi()
    await w.vm.save()
    await flushPromises()
    expect(mappingWrites()).toHaveLength(2)
    expect(mappingWrites()[1].method.toUpperCase()).toBe('PUT')
    noRangeKeys(body(mappingWrites()[1]))
  })
})

describe('身分來源詳情：連線設定變更提示', () => {
  const NOTICE = '[data-test="config-change-notice"]'
  const ldapView = {
    configured: true,
    id: 1,
    name: '公司目錄',
    url: 'ldaps://a.example.com:636',
    bind_dn: 'cn=svc,dc=example,dc=com',
    has_bind_password: true,
    base_dn: 'ou=users,dc=example,dc=com',
    user_filter: '(uid=%s)',
    attr_email: 'mail',
    attr_fullname: 'cn',
    attr_group: 'memberOf',
    skip_tls_verify: false,
    enabled: true,
  }
  const oidcView = {
    id: 5,
    name: 'corp',
    issuer: 'https://idp.example.com',
    client_id: 'cid',
    scopes: 'openid profile email',
    groups_claim: '',
    admission_mode: 'jit_with_rules',
    admission_rules: '{"tid":["t-1"]}',
    has_secret: true,
    enabled: true,
    redirect_uri: 'https://bastion.example.com/api/v1/auth/oidc/callback',
    redirect_uri_state: 'ready',
  }
  const sourceRequests = () =>
    h.request.mockImplementation(async (c) => {
      const key = `${c.method.toUpperCase()} ${c.url}`
      if (key === 'GET /ldap-directory') return ldapView
      if (key === 'GET /oidc-providers/5') return { data: oidcView }
      if (key === 'GET /identity-sources') return { data: [] }
      return {}
    })
  const mountSource = async (comp, params) => {
    h.route = reactive({ params, query: {} })
    const w = mount(comp, {
      global: { plugins: [ElementPlus], stubs: { 'router-link': { template: '<a><slot /></a>' } } },
    })
    await flushPromises()
    return w
  }

  it('LDAP：改連線位址出現會通知安全人員的提示，改回原值後消失', async () => {
    sourceRequests()
    const w = await mountSource(LDAPSourceDetail, {})
    expect(w.find(NOTICE).exists()).toBe(false)

    w.vm.form.url = 'ldaps://b.example.com:636'
    await flushPromises()
    expect(w.find(NOTICE).text()).toContain(t('identitySources.configChangeNotice'))
    expect(t('identitySources.configChangeNotice')).toContain('通知安全人員')

    w.vm.form.url = ldapView.url
    await flushPromises()
    expect(w.find(NOTICE).exists()).toBe(false)
  })

  it('OIDC：改使用者名稱宣告出現提示，改回原值後消失', async () => {
    sourceRequests()
    const w = await mountSource(OIDCSourceDetail, { id: '5' })
    expect(w.find(NOTICE).exists()).toBe(false)

    w.vm.form.username_claim = 'upn'
    await flushPromises()
    expect(w.find(NOTICE).text()).toContain(t('identitySources.configChangeNotice'))

    w.vm.form.username_claim = ''
    await flushPromises()
    expect(w.find(NOTICE).exists()).toBe(false)
  })

  it('三語都有同名鍵且非空', () => {
    for (const loc of [zhTW, enUS, jaJP]) {
      expect(loc.identitySources.configChangeNotice.length).toBeGreaterThan(0)
    }
  })
})
