import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import UserRoleScopeTab from '../components/UserRoleScopeTab.vue'
import { ElDialogStub } from '@/__fixtures__/dialogStub'
import { applyCurrentUser, resetCapabilities } from '@/composables/useCapabilities'
import i18n from '@/i18n'

enableAutoUnmount(afterEach)

const h = vi.hoisted(() => ({ request: vi.fn(), push: vi.fn() }))

vi.mock('@/api/request', () => ({ default: (...a) => h.request(...a) }))
vi.mock('vue-router', () => ({
  useRoute: () => ({ params: {}, query: {} }),
  useRouter: () => ({ push: h.push, replace: vi.fn() }),
}))

const t = (k, p) => i18n.global.t(k, p)
const err = (status, code) => ({ response: { status, data: { error: { code } } } })

const defs = [
  { id: 1, name: 'auditor', builtin_key: 'auditor', scopable: false, node_range_no_effect: false, assignment_state: 'open', management_class: false },
  { id: 2, name: 'approver', builtin_key: 'approver', scopable: false, node_range_no_effect: false, assignment_state: 'open', management_class: false },
  { id: 3, name: 'asset_admin', builtin_key: 'asset_admin', scopable: true, node_range_no_effect: false, assignment_state: 'open', management_class: true },
  { id: 4, name: 'user', builtin_key: 'user', scopable: true, node_range_no_effect: true, assignment_state: 'open', management_class: false },
  { id: 5, name: 'duty_contact', builtin_key: '', scopable: true, node_range_no_effect: true, assignment_state: 'open', management_class: false },
]
const NODES = [
  { id: 11, name: '甲節點', parent_id: null, depth: 1, path: '甲節點', subtree_asset_count: 12 },
  { id: 12, name: '乙節點', parent_id: null, depth: 1, path: '乙節點', subtree_asset_count: 6 },
]
const noOp = { marks: [], self_direction: '', routes_gained: [], routes_lost: [], evaluated: 0 }
const basePreview = { total: 0, matched: 0, truncated: false, subjects: [], operation: noOp }

let cfg
const setup = (over = {}) => {
  cfg = {
    options: {
      nodes: NODES,
      node_assignable_role_ids: [3, 4, 5],
      node_range_no_effect_role_ids: [4, 5],
      node_range_no_effect_reasons: { 4: 'builtin_global_only', 5: 'no_scoped_permission' },
    },
    userBindings: { data: [] },
    preview: { ...basePreview, managed_assets: { before: 6, after: 18 }, role_assets: [] },
    putError: null,
    putExtra: null,
    groups: [],
    groupBindings: {},
    ...over,
  }
  h.request.mockImplementation(async (c) => {
    const key = `${c.method.toUpperCase()} ${c.url}`
    if (key === 'GET /role-definitions') return { data: defs, total: defs.length, can_define: false }
    if (key === 'GET /user-groups') return { data: cfg.groups }
    const gb = /^GET \/user-groups\/(\d+)\/role-bindings$/.exec(key)
    if (gb) return { data: cfg.groupBindings[gb[1]] || [] }
    if (key === 'GET /role-assignment-options') return cfg.options
    if (key === 'GET /users/9/role-bindings') return cfg.userBindings
    if (key === 'POST /role-assignment-previews') return cfg.preview
    if (key === 'PUT /users/9/roles') {
      if (cfg.putError) throw cfg.putError
      return { ...(cfg.putExtra || {}), role_sets: { manual: c.data.manual_roles, mapped: [] } }
    }
    throw new Error(`unexpected request ${key}`)
  })
}
const calls = (method, url) =>
  h.request.mock.calls.map((c) => c[0]).filter((c) => c.method.toUpperCase() === method && c.url === url)

const asAssigner = () => applyCurrentUser({ id: 1, permissions: ['user:manage', 'role:assign'] })

const mountTab = async (props = {}) => {
  const w = mount(UserRoleScopeTab, {
    props: { userId: 9, username: 'target', roleSets: { manual: ['auditor'], mapped: [] }, ...props },
    global: { plugins: [ElementPlus], stubs: { ElDialog: ElDialogStub } },
  })
  await flushPromises()
  return w
}
const wait = (ms) => new Promise((r) => setTimeout(r, ms))
// 範圍不會生效的角色以全系統持有時點卡片不開節點選擇，改經「更多」的「仍要限定節點」
const open = async (w, role) => {
  await w.get(`[data-test="manual-role-${role}"]`).trigger('click')
  await flushPromises()
  const more = w.find(`[data-test="more-${role}"]`)
  if (more.exists() && !w.find('[data-test="range-panel"]').exists()) {
    await more.trigger('click')
    await w.get(`[data-test="still-limit-${role}"]`).trigger('click')
    await flushPromises()
  }
}
const setMode = async (w, mode) => {
  await w.get(`[data-test="rnp-mode-${mode}"] input`).setValue(true)
  await flushPromises()
}
const pickNode = async (w, id, on = true) => {
  await w.get(`[data-test="rnp-check-${id}"] input`).setValue(on)
  await flushPromises()
}
const save = async (w) => {
  await w.get('[data-test="roles-save"]').trigger('click')
  await flushPromises()
}
const lastPut = () => {
  const puts = calls('PUT', '/users/9/roles')
  return puts[puts.length - 1]?.data
}

beforeEach(() => {
  h.request.mockReset()
  h.push.mockReset()
  resetCapabilities()
  i18n.global.locale.value = 'zh-TW'
  setup()
})

describe('使用者角色與範圍：節點範圍', () => {
  it('伺服器清單內的角色有可限範圍標籤，其餘不需要選範圍且點擊不開節點樹', async () => {
    asAssigner()
    const w = await mountTab({ roleSets: { manual: ['asset_admin', 'user', 'auditor'], mapped: [] } })
    expect(w.get('[data-test="tag-assignable-asset_admin"]').text()).toBe(t('roleNodePicker.tagAssignable'))
    expect(w.get('[data-test="tag-no-range-auditor"]').text()).toBe(t('roleNodePicker.tagNoRange'))
    await open(w, 'auditor')
    expect(w.find('[data-test="range-panel"]').exists()).toBe(false)
    expect(w.find('[data-test="rnp-tree"]').exists()).toBe(false)
    // 一般使用者（內建只在全系統生效）：不適用、無可限範圍標籤、點卡片不開節點選擇；
    // 「更多」內先說明不會生效再給「仍要限定節點」，選它後可切到指定節點並照常送出
    const userCard = w.get('[data-test="manual-role-user"]').text()
    expect(userCard).toContain(t('roles.list.scopeNotApplicable'))
    expect(userCard).toContain('以全系統指派')
    expect(w.find('[data-test="tag-assignable-user"]').exists()).toBe(false)
    await w.get('[data-test="manual-role-user"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="range-panel"]').exists()).toBe(false)
    expect(w.find('[data-test="rnp-tree"]').exists()).toBe(false)
    await w.get('[data-test="more-user"]').trigger('click')
    const more = w.get('[data-test="more-panel-user"]').element.textContent
    expect(more.indexOf(t('roleNodePicker.builtinGlobalOnlyNote'))).toBeGreaterThanOrEqual(0)
    expect(more.indexOf(t('roleNodePicker.builtinGlobalOnlyNote'))).toBeLessThan(more.indexOf(t('roleNodePicker.stillLimitNodes')))
    await w.get('[data-test="still-limit-user"]').trigger('click')
    await flushPromises()
    await setMode(w, 'nodes')
    expect(w.find('[data-test="rnp-tree"]').exists()).toBe(true)
    expect(w.text()).toContain(t('roleNodePicker.builtinGlobalOnlyNote'))
    expect(w.text()).not.toContain(t('roleNodePicker.rangeNoEffectNote'))
    await pickNode(w, 11)
    await save(w)
    expect(lastPut().role_nodes).toEqual({ user: [11] })
  })

  it('讀取端點以 node_ids 欄位存在判定節點範圍，不以陣列長度', async () => {
    asAssigner()
    setup({
      userBindings: {
        data: [
          { role_id: 3, role_name: 'asset_admin', source: 'manual', node_ids: [11] },
          { role_id: 5, role_name: 'duty_contact', source: 'manual', node_ids: [] },
          { role_id: 1, role_name: 'auditor', source: 'manual' },
        ],
      },
    })
    const w = await mountTab({ roleSets: { manual: ['asset_admin', 'duty_contact', 'auditor'], mapped: [] } })
    expect(w.get('[data-test="range-paths-asset_admin"]').text()).toContain('甲節點')
    expect(w.find('[data-test="range-all-asset_admin"]').exists()).toBe(false)
    expect(w.find('[data-test="range-paths-duty_contact"]').exists()).toBe(true)
    expect(w.find('[data-test="range-all-duty_contact"]').exists()).toBe(false)
    expect(w.get('[data-test="range-all-auditor"]').exists()).toBe(true)
  })

  it('開啟已有節點範圍的分頁讀一次台數；只改既有角色的範圍時再排程一次並帶角色範圍', async () => {
    asAssigner()
    setup({
      userBindings: { data: [{ role_id: 3, role_name: 'asset_admin', source: 'manual', node_ids: [11] }] },
    })
    const w = await mountTab({ roleSets: { manual: ['asset_admin'], mapped: [] } })
    await wait(500)
    await flushPromises()
    let pv = calls('POST', '/role-assignment-previews')
    expect(pv).toHaveLength(1)
    expect(pv[0].data.include_managed_asset_counts).toBe(true)
    expect(pv[0].data.role_nodes).toBeUndefined()
    await open(w, 'asset_admin')
    await pickNode(w, 12)
    await wait(500)
    await flushPromises()
    pv = calls('POST', '/role-assignment-previews')
    expect(pv).toHaveLength(2)
    expect(pv[1].data.include_managed_asset_counts).toBe(true)
    expect(pv[1].data.role_ids).toEqual([3])
    expect(pv[1].data.role_nodes).toEqual({ 3: [11, 12] })
  })

  it('新加入可限定節點的角色未改範圍即儲存：請求不含 role_nodes，卡片顯示全系統且無台數', async () => {
    asAssigner()
    const w = await mountTab()
    await w.vm.addPicked('asset_admin')
    await flushPromises()
    expect(w.get('[data-test="range-all-asset_admin"]').text()).toBe(t('roleNodePicker.modeAll'))
    expect(w.get('[data-test="manual-role-asset_admin"]').text()).not.toContain(t('roleNodePicker.cardCount', { n: 12 }))
    await save(w)
    const body = lastPut()
    expect(body.manual_roles).toEqual(['auditor', 'asset_admin'])
    expect(Object.keys(body)).toEqual(['manual_roles'])
  })

  it('切到指定節點勾甲節點後儲存：只為該角色帶節點，卡片顯示路徑與台數，變化面板取自預覽', async () => {
    asAssigner()
    const w = await mountTab()
    await w.vm.addPicked('asset_admin')
    await flushPromises()
    await open(w, 'asset_admin')
    await setMode(w, 'nodes')
    await pickNode(w, 11)
    const card = w.get('[data-test="range-paths-asset_admin"]').text()
    expect(card).toContain('甲節點')
    expect(card).toContain(t('roleNodePicker.cardCount', { n: 12 }))
    await wait(500)
    await flushPromises()
    const pvBody = calls('POST', '/role-assignment-previews').pop().data
    expect(pvBody.include_managed_asset_counts).toBe(true)
    expect(w.get('[data-test="change-managed-assets"]').text()).toContain(
      t('roleNodePicker.changeAssetsValue', { after: 18, before: 6 })
    )
    await save(w)
    expect(lastPut().role_nodes).toEqual({ asset_admin: [11] })
  })

  it('儲存只為改動範圍的角色帶 role_nodes', async () => {
    asAssigner()
    const bindings = {
      data: [
        { role_id: 3, role_name: 'asset_admin', source: 'manual', node_ids: [11] },
        { role_id: 4, role_name: 'user', source: 'manual' },
      ],
    }
    const roleSets = { manual: ['asset_admin', 'user'], mapped: [] }
    // 只移除另一個角色：不帶範圍鍵
    setup({ userBindings: bindings })
    let w = await mountTab({ roleSets })
    await w.get('[data-test="remove-user"]').trigger('click')
    await save(w)
    expect(lastPut().manual_roles).toEqual(['asset_admin'])
    expect(lastPut().role_nodes).toBeUndefined()
    // 改為乙節點
    setup({ userBindings: bindings })
    w = await mountTab({ roleSets })
    await open(w, 'asset_admin')
    await pickNode(w, 11, false)
    await pickNode(w, 12)
    await save(w)
    expect(lastPut().role_nodes).toEqual({ asset_admin: [12] })
    // 改為全系統
    setup({ userBindings: bindings })
    w = await mountTab({ roleSets })
    await open(w, 'asset_admin')
    await setMode(w, 'all')
    await save(w)
    expect(lastPut().role_nodes).toEqual({ asset_admin: null })
    // 新加入角色切到指定節點再切回全系統：不帶它的鍵
    setup({ userBindings: bindings })
    w = await mountTab({ roleSets })
    await w.vm.addPicked('duty_contact')
    await flushPromises()
    await open(w, 'duty_contact')
    await setMode(w, 'nodes')
    await setMode(w, 'all')
    await w.get('[data-test="remove-user"]').trigger('click')
    await save(w)
    expect(lastPut().manual_roles).toEqual(['asset_admin', 'duty_contact'])
    expect(lastPut().role_nodes).toBeUndefined()
    // 新加入維持全系統的角色，同時改動既有角色的範圍：只帶既有角色
    setup({ userBindings: bindings })
    w = await mountTab({ roleSets })
    await w.vm.addPicked('duty_contact')
    await flushPromises()
    await open(w, 'asset_admin')
    await pickNode(w, 11, false)
    await pickNode(w, 12)
    await save(w)
    expect(Object.keys(lastPut().role_nodes)).toEqual(['asset_admin'])
    expect(lastPut().role_nodes.asset_admin).toEqual([12])
  })

  it('伺服器回節點無效：顯示該碼譯文，角色清單與範圍草稿不變', async () => {
    asAssigner()
    setup({ putError: err(400, 'VALIDATION_ROLE_BINDING_NODES_INVALID') })
    const w = await mountTab()
    await w.vm.addPicked('asset_admin')
    await flushPromises()
    await open(w, 'asset_admin')
    await setMode(w, 'nodes')
    await pickNode(w, 11)
    await save(w)
    expect(w.get('[data-test="assign-error"]').text()).toBe(t('apiError.VALIDATION_ROLE_BINDING_NODES_INVALID'))
    expect(w.findAll('[data-test^="manual-role-"]').map((e) => e.attributes('data-test'))).toEqual([
      'manual-role-auditor',
      'manual-role-asset_admin',
    ])
    expect(w.get('[data-test="range-paths-asset_admin"]').text()).toContain('甲節點')
  })

  it('只有使用者管理能力：不讀節點清單，卡片只顯示節點數，沒有節點名稱、台數與節點樹', async () => {
    applyCurrentUser({ id: 1, permissions: ['user:manage'] })
    setup({
      userBindings: { data: [{ role_id: 3, role_name: 'asset_admin', source: 'manual', node_ids: [11, 12] }] },
    })
    const w = await mountTab({ roleSets: { manual: ['asset_admin'], mapped: [] } })
    await open(w, 'asset_admin')
    expect(calls('GET', '/role-assignment-options')).toHaveLength(0)
    const card = w.get('[data-test="manual-role-asset_admin"]').text()
    expect(card).toContain(t('roleNodePicker.nodeCountOnly', { n: 2 }))
    expect(w.text()).not.toContain('甲節點')
    expect(w.text()).not.toContain('乙節點')
    expect(w.text()).not.toContain('12 台')
    expect(w.find('[data-test="range-panel"]').exists()).toBe(false)
    expect(w.find('[data-test="rnp-tree"]').exists()).toBe(false)
  })

  it('取消勾選並存來源的角色：該列提示仍由外部群組給予，限定節點者另提示改為全系統，不擋儲存', async () => {
    applyCurrentUser({ id: 1, permissions: ['user:manage'] })
    setup({
      userBindings: {
        data: [
          { role_id: 2, role_name: 'approver', source: 'both', node_ids: [11] },
          { role_id: 1, role_name: 'auditor', source: 'both' },
        ],
      },
    })
    const w = await mountTab({ roleSets: { manual: ['approver', 'auditor'], mapped: ['approver', 'auditor'] } })
    expect(w.find('[data-test="both-removed-hint-approver"]').exists()).toBe(false)
    expect(w.find('[data-test="both-removed-hint-auditor"]').exists()).toBe(false)
    await w.get('[data-test="remove-approver"]').trigger('click')
    await w.get('[data-test="remove-auditor"]').trigger('click')
    expect(w.get('[data-test="both-removed-hint-approver"]').text()).toBe(t('roleNodePicker.mappedStillGranted'))
    expect(w.get('[data-test="both-removed-hint-auditor"]').text()).toBe(t('roleNodePicker.mappedStillGrantedGlobal'))
    expect(w.find('[data-test="roles-save"]').attributes('disabled')).toBeUndefined()
    await save(w)
    expect(calls('PUT', '/users/9/roles')).toHaveLength(1)
  })

  it('失效節點：標示且不顯示名稱，按移除前不寫入，儲存只帶有效節點', async () => {
    asAssigner()
    setup({
      userBindings: { data: [{ role_id: 3, role_name: 'asset_admin', source: 'manual', node_ids: [11, 99] }] },
    })
    const w = await mountTab({ roleSets: { manual: ['asset_admin'], mapped: [] } })
    expect(w.get('[data-test="missing-tag-asset_admin"]').text()).toBe(t('roleNodePicker.nodeMissing'))
    expect(w.get('[data-test="missing-note-asset_admin"]').text()).toBe(t('roleNodePicker.nodeMissingNote', { n: 1 }))
    expect(w.get('[data-test="manual-role-asset_admin"]').text()).not.toContain('99')
    expect(calls('PUT', '/users/9/roles')).toHaveLength(0)
    await w.get('[data-test="remove-missing-asset_admin"]').trigger('click')
    await flushPromises()
    expect(calls('PUT', '/users/9/roles')).toHaveLength(0)
    expect(w.find('[data-test="missing-tag-asset_admin"]').exists()).toBe(false)
    await save(w)
    expect(lastPut().role_nodes).toEqual({ asset_admin: [11] })
  })

  it('全部失效時移除：仍是指定節點並顯示至少一個節點的文案，草稿不變成全系統，儲存鈕仍可按', async () => {
    asAssigner()
    setup({
      putError: err(400, 'VALIDATION_ROLE_BINDING_NODES_EMPTY'),
      userBindings: { data: [{ role_id: 3, role_name: 'asset_admin', source: 'manual', node_ids: [98, 99] }] },
    })
    const w = await mountTab({ roleSets: { manual: ['asset_admin'], mapped: [] } })
    await w.get('[data-test="remove-missing-asset_admin"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="nodes-empty-asset_admin"]').text()).toBe(t('apiError.VALIDATION_ROLE_BINDING_NODES_EMPTY'))
    expect(w.find('[data-test="range-all-asset_admin"]').exists()).toBe(false)
    expect(w.get('[data-test="roles-save"]').attributes('disabled')).toBeUndefined()
    await save(w)
    expect(lastPut().role_nodes).toEqual({ asset_admin: [] })
    expect(lastPut().role_nodes.asset_admin).not.toBeNull()
    expect(w.get('[data-test="assign-error"]').text()).toBe(t('apiError.VALIDATION_ROLE_BINDING_NODES_EMPTY'))
    expect(w.find('[data-test="range-all-asset_admin"]').exists()).toBe(false)
  })

  it('來自群組的失效節點只標示，沒有移除鈕，有到群組修改的連結', async () => {
    asAssigner()
    setup({
      groups: [{ id: 5, name: 'SRE', member_sources: [{ user_id: 9, manual: true, mapped: false }] }],
      groupBindings: { 5: [{ role_id: 3, role_name: 'asset_admin', scope: 'nodes', node_ids: [11, 99] }] },
    })
    const w = await mountTab()
    expect(w.get('[data-test="group-missing-tag-5"]').text()).toBe(t('roleNodePicker.nodeMissing'))
    expect(w.get('[data-test="group-missing-note-5"]').text()).toBe(t('roleNodePicker.nodeMissingNote', { n: 1 }))
    expect(w.get('[data-test="group-block"]').text()).not.toContain(t('roleNodePicker.removeMissing'))
    expect(w.get('[data-test="group-link-5"]').exists()).toBe(true)
  })

  it('目前不能限定節點的節點範圍角色：有說明、節點樹不可開、全系統與移除可用；只移除第三個角色不帶這兩個角色的範圍鍵', async () => {
    asAssigner()
    setup({
      userBindings: {
        data: [
          { role_id: 3, role_name: 'asset_admin', source: 'manual', node_ids: [11, 99] },
          { role_id: 1, role_name: 'auditor', source: 'manual', node_ids: [12] },
          { role_id: 4, role_name: 'user', source: 'manual' },
        ],
      },
    })
    const w = await mountTab({ roleSets: { manual: ['asset_admin', 'auditor', 'user'], mapped: [] } })
    expect(w.get('[data-test="global-only-note-auditor"]').text()).toBe(t('roleNodePicker.globalOnlyNote'))
    expect(w.find('[data-test="global-only-note-asset_admin"]').exists()).toBe(false)
    await open(w, 'auditor')
    expect(w.find('[data-test="range-panel"]').exists()).toBe(false)
    expect(w.find('[data-test="rnp-tree"]').exists()).toBe(false)
    expect(w.find('[data-test="set-all-auditor"]').exists()).toBe(true)
    expect(w.find('[data-test="remove-auditor"]').exists()).toBe(true)
    await w.get('[data-test="remove-user"]').trigger('click')
    await save(w)
    expect(calls('PUT', '/users/9/roles')).toHaveLength(1)
    expect(lastPut().manual_roles).toEqual(['asset_admin', 'auditor'])
    expect(lastPut().role_nodes).toBeUndefined()
    expect(w.find('[data-test="assign-error"]').exists()).toBe(false)
    // 改為全系統是可用的
    await w.get('[data-test="set-all-auditor"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="range-all-auditor"]').exists()).toBe(true)
  })

  it('範圍不會生效的角色照常選節點與儲存，卡片依原因提示且不出現不能限定節點的說明', async () => {
    asAssigner()
    const w = await mountTab()
    await w.vm.addPicked('duty_contact')
    await flushPromises()
    await open(w, 'duty_contact')
    await setMode(w, 'nodes')
    await pickNode(w, 11)
    expect(w.get('[data-test="card-no-effect-duty_contact"]').text()).toBe(t('roleNodePicker.rangeNoEffectNote'))
    expect(w.text()).not.toContain(t('roleNodePicker.globalOnlyNote'))
    expect(w.text()).not.toContain(t('roleNodePicker.builtinGlobalOnlyNote'))
    expect(w.get('[data-test="roles-save"]').attributes('disabled')).toBeUndefined()
    await save(w)
    expect(lastPut().role_nodes).toEqual({ duty_contact: [11] })
    // 切回全系統後卡片層提示消失，改在範圍欄說明全系統持有時範圍不會生效
    await setMode(w, 'all')
    expect(w.find('[data-test="card-no-effect-duty_contact"]').exists()).toBe(false)
    expect(w.get('[data-test="range-no-effect-duty_contact"]').text()).toBe(t('roleNodePicker.rangeNoEffectNote'))
  })

  it('範圍不會生效的原因為內建角色只在全系統生效時，提示改為內建角色說明，操作與送出不變', async () => {
    asAssigner()
    setup({
      options: {
        nodes: NODES,
        node_assignable_role_ids: [3, 4, 5],
        node_range_no_effect_role_ids: [5],
        node_range_no_effect_reasons: { 5: 'builtin_global_only' },
      },
      putExtra: { node_range_no_effect: [{ role: 'duty_contact', reason: 'builtin_global_only' }] },
    })
    const w = await mountTab()
    await w.vm.addPicked('duty_contact')
    await flushPromises()
    await open(w, 'duty_contact')
    await setMode(w, 'nodes')
    await pickNode(w, 11)
    expect(w.get('[data-test="card-no-effect-duty_contact"]').text()).toBe(t('roleNodePicker.builtinGlobalOnlyNote'))
    expect(w.text()).not.toContain(t('roleNodePicker.rangeNoEffectNote'))
    await save(w)
    expect(lastPut().role_nodes).toEqual({ duty_contact: [11] })
    // 寫入回應帶不生效清單：不另出現錯誤
    expect(w.find('[data-test="assign-error"]').exists()).toBe(false)
  })
  it('角色定義晚於指派讀回到達：定義到齊前不送預覽，到齊後送出的本文含全部角色編號', async () => {
    asAssigner()
    setup({
      userBindings: {
        data: [
          { role_id: 3, role_name: 'asset_admin', source: 'manual', node_ids: [11] },
          { role_id: 1, role_name: 'auditor', source: 'manual' },
        ],
      },
    })
    const base = h.request.getMockImplementation()
    let release
    const gate = new Promise((r) => { release = r })
    h.request.mockImplementation(async (c) => {
      if (`${c.method.toUpperCase()} ${c.url}` === 'GET /role-definitions') await gate
      return base(c)
    })
    await mountTab({ roleSets: { manual: ['asset_admin', 'auditor'], mapped: [] } })
    await wait(500)
    await flushPromises()
    expect(calls('POST', '/role-assignment-previews')).toHaveLength(0)
    release()
    await flushPromises()
    await wait(500)
    await flushPromises()
    const pv = calls('POST', '/role-assignment-previews')
    expect(pv.length).toBeGreaterThan(0)
    for (const c of pv) expect([...c.data.role_ids].sort()).toEqual([1, 3])
  })

  it('來自群組的列：節點範圍的角色顯示路徑與台數，全系統的角色不列路徑', async () => {
    asAssigner()
    setup({
      groups: [{ id: 5, name: 'SRE', member_sources: [{ user_id: 9, manual: true, mapped: false }] }],
      groupBindings: {
        5: [
          { role_id: 3, role_name: 'asset_admin', scope: 'nodes', node_ids: [11] },
          { role_id: 1, role_name: 'auditor', scope: 'all' },
        ],
      },
    })
    const w = await mountTab()
    const row = w.get('[data-test="group-range-5-asset_admin"]').text()
    expect(row).toContain('甲節點')
    expect(row).toContain(t('roleNodePicker.cardCount', { n: 12 }))
    expect(w.find('[data-test="group-range-5-auditor"]').exists()).toBe(false)
  })

  it('來自群組的列：同一角色有多個群組來源時只列路徑不附台數', async () => {
    asAssigner()
    const src = [{ user_id: 9, manual: true, mapped: false }]
    setup({
      groups: [
        { id: 5, name: 'SRE', member_sources: src },
        { id: 6, name: 'OPS', member_sources: src },
      ],
      groupBindings: {
        5: [{ role_id: 3, role_name: 'asset_admin', scope: 'nodes', node_ids: [11] }],
        6: [{ role_id: 3, role_name: 'asset_admin', scope: 'nodes', node_ids: [12] }],
      },
    })
    const w = await mountTab()
    const row = w.get('[data-test="group-range-5-asset_admin"]').text()
    expect(row).toContain('甲節點')
    expect(row).not.toContain(t('roleNodePicker.cardCount', { n: 12 }))
  })

  it('來自群組的列：沒有指派能力者只顯示節點數，不讀節點清單', async () => {
    applyCurrentUser({ id: 1, permissions: ['user:manage'] })
    setup({
      groups: [{ id: 5, name: 'SRE', member_sources: [{ user_id: 9, manual: true, mapped: false }] }],
      groupBindings: { 5: [{ role_id: 3, role_name: 'asset_admin', scope: 'nodes', node_ids: [11, 12] }] },
    })
    const w = await mountTab()
    const row = w.get('[data-test="group-range-count-5-asset_admin"]').text()
    expect(row).toContain(t('roleNodePicker.nodeCountOnly', { n: 2 }))
    expect(w.get('[data-test="group-block"]').text()).not.toContain('甲節點')
  })
})

describe('使用者角色與範圍：分配角色選單與管理範圍說明（3.8、3.10）', () => {
  const bigDefs = () => {
    const d = [
      ...defs,
      { id: 6, name: 'authz_admin', builtin_key: 'authz_admin', scopable: true, node_range_no_effect: false },
      { id: 7, name: 'bx7', builtin_key: 'bx7', scopable: false, node_range_no_effect: false },
      { id: 8, name: 'bx8', builtin_key: 'bx8', scopable: false, node_range_no_effect: false },
    ].map((x) => ({ assignment_state: 'open', management_class: false, ...x }))
    // 內建 8 個（1、2、3、4、6、7、8 加 5 改成內建不成立）：5 為自訂，再補 15 個自訂
    for (let i = 9; i <= 23; i++) {
      d.push({ id: i, name: i === 9 ? '資產盤點助理' : `自訂角色${i}`, builtin_key: '', scopable: i === 9, node_range_no_effect: false, assignment_state: 'open', management_class: false })
    }
    return d
  }
  const mountBig = async (props = {}) => {
    setup({
      options: {
        nodes: NODES,
        node_assignable_role_ids: [3, 4, 5, 6, 9],
        node_range_no_effect_role_ids: [4, 5],
        node_range_no_effect_reasons: { 4: 'builtin_global_only', 5: 'no_scoped_permission' },
      },
    })
    const base = h.request.getMockImplementation()
    const big = bigDefs()
    h.request.mockImplementation(async (c) =>
      `${c.method.toUpperCase()} ${c.url}` === 'GET /role-definitions' ? { data: big, total: big.length, can_define: false } : base(c)
    )
    asAssigner()
    const el = document.createElement('div')
    document.body.appendChild(el)
    const w = mount(UserRoleScopeTab, {
      attachTo: el,
      props: { userId: 9, username: 'target', roleSets: { manual: [], mapped: [] }, ...props },
      global: { plugins: [ElementPlus], stubs: { ElDialog: ElDialogStub } },
    })
    await flushPromises()
    return w
  }
  const bodyOptions = () => [...document.body.querySelectorAll('[data-test^="role-option-"]')]

  it('選單掛在頁面層、可篩選、分內建與自訂兩組並標可限管理範圍', async () => {
    const w = await mountBig()
    await w.get('[data-test="role-pick"] .el-select__wrapper').trigger('click')
    await flushPromises()
    const root = w.get('[data-test="role-scope-tab"]').element
    const opts = bodyOptions()
    expect(opts.length).toBe(23)
    expect(opts.every((o) => !root.contains(o) && document.body.contains(o))).toBe(true)
    expect(document.body.querySelector('[data-test="role-option-asset_admin"]')).not.toBeNull()
    const titles = [...document.body.querySelectorAll('.el-select-group__title')].map((e) => e.textContent.trim())
    expect(titles).toEqual([t('roles.list.builtinTitle', { n: 7 }), t('roles.list.customTitle', { n: 16 })])
    const tagged = (n) => document.body.querySelector(`[data-test="option-scopable-${n}"]`) !== null
    expect(tagged('asset_admin')).toBe(true)
    expect(tagged('authz_admin')).toBe(true)
    expect(tagged('資產盤點助理')).toBe(true)
    expect(tagged('user')).toBe(false)
    expect(tagged('auditor')).toBe(false)
    expect(tagged('duty_contact')).toBe(false)
    await w.get('[data-test="role-pick"] input').setValue('資產')
    await flushPromises()
    const shown = bodyOptions().filter((o) => !o.closest('[style*="display: none"]')).map((o) => o.textContent)
    expect(shown.length).toBeGreaterThan(0)
    expect(shown.length).toBeLessThan(23)
    expect(shown.every((x) => x.includes('資產'))).toBe(true)
    w.unmount()
  })

  it('在更多內按仍要限定節點後，焦點移到展開的範圍面板，不掉到頁面最外層', async () => {
    const w = await mountBig({ roleSets: { manual: ['user'], mapped: [] } })
    await w.get('[data-test="manual-role-user"]').trigger('click')
    await flushPromises()
    await w.get('[data-test="more-user"]').trigger('click')
    w.get('[data-test="still-limit-user"]').element.focus()
    await w.get('[data-test="still-limit-user"]').trigger('click')
    await flushPromises()
    expect(document.activeElement).toBe(w.get('[data-test="range-panel"]').element)
  })

  it('頂部說明含管理範圍說明與連線句，連結不帶主體，只在能進資產授權頁時出現', async () => {
    const w = await mountBig()
    const txt = w.get('[data-test="scope-banner"]').text()
    expect(txt).toContain(t('roleScope.bannerTitle'))
    expect(txt).toContain(t('roleScope.bannerBody'))
    expect(txt).toContain(t('userDetail.change.connectionFixed'))
    expect(w.find('[data-test="banner-go-authorizations"]').exists()).toBe(false)
    w.unmount()
    applyCurrentUser({ id: 1, permissions: ['user:manage', 'role:assign', 'authorization:manage'] })
    const el = document.createElement('div')
    document.body.appendChild(el)
    const w2 = mount(UserRoleScopeTab, {
      attachTo: el,
      props: { userId: 9, username: 'target', roleSets: { manual: [], mapped: [] } },
      global: { plugins: [ElementPlus], stubs: { ElDialog: ElDialogStub } },
    })
    await flushPromises()
    const links = w2.findAll('[data-test="banner-go-authorizations"]')
    expect(links).toHaveLength(1)
    expect(links[0].attributes('href')).toBe('/authorizations')
    w2.unmount()
  })
})


describe('儲存後的變化與選單篩選（使用者）', () => {
  const titles = () => [...document.body.querySelectorAll('.el-select-group__title')].map((e) => e.textContent.trim())
  const mountAttached = async () => {
    asAssigner()
    const el = document.createElement('div')
    document.body.appendChild(el)
    const w = mount(UserRoleScopeTab, {
      attachTo: el,
      props: { userId: 9, username: 'target', roleSets: { manual: ['auditor'], mapped: [] } },
      global: { plugins: [ElementPlus], stubs: { ElDialog: ElDialogStub } },
    })
    await flushPromises()
    return w
  }

  it('可連線主機列寫「不變」，不帶台數，並保留既有說明句', async () => {
    asAssigner()
    const w = await mountTab()
    await w.vm.addPicked('asset_admin')
    await wait(500)
    await flushPromises()
    expect(w.get('[data-test="change-connection-value"]').text()).toBe(t('userDetail.change.connectionUnchanged'))
    expect(t('userDetail.change.connectionUnchanged')).toBe('不變')
    expect(w.get('[data-test="change-connection-value"]').text()).not.toMatch(/\d/)
    expect(w.get('[data-test="change-connection"]').text()).toBe(t('userDetail.change.connectionFixed'))
  })

  it('全系統持有可限範圍角色時寫「全部資產」不寫 0 台；改成節點範圍後回到台數', async () => {
    setup({ preview: { ...basePreview, managed_assets: { before: 0, after: 0 }, role_assets: [] } })
    asAssigner()
    const w = await mountTab()
    await w.vm.addPicked('asset_admin')
    await wait(500)
    await flushPromises()
    const row = w.get('[data-test="change-managed-assets"]')
    expect(w.get('[data-test="change-managed-assets-all"]').text()).toBe(t('roleNodePicker.changeAssetsAll'))
    expect(row.text()).toContain('全部資產')
    expect(row.text()).not.toContain('0 台')
    await open(w, 'asset_admin')
    await setMode(w, 'nodes')
    await pickNode(w, 11)
    await wait(500)
    await flushPromises()
    expect(w.find('[data-test="change-managed-assets-all"]').exists()).toBe(false)
    expect(w.get('[data-test="change-managed-assets"]').text()).toContain(t('roleNodePicker.changeAssetsValue', { after: 0, before: 0 }))
  })

  it('判定看範圍分類而非角色名稱（範圍不會生效的一般使用者全系統不寫全部資產）', async () => {
    setup({ preview: { ...basePreview, managed_assets: { before: 0, after: 0 }, role_assets: [] } })
    asAssigner()
    const w = await mountTab()
    await w.vm.addPicked('user')
    await wait(500)
    await flushPromises()
    expect(w.find('[data-test="change-managed-assets-all"]').exists()).toBe(false)
    expect(w.get('[data-test="change-managed-assets"]').text()).toContain(t('roleNodePicker.changeAssetsValue', { after: 0, before: 0 }))
  })

  it('篩選時內建與自訂兩組的組標數字隨結果更新，清除篩選後還原', async () => {
    const w = await mountAttached()
    await w.get('[data-test="role-pick"] .el-select__wrapper').trigger('click')
    await flushPromises()
    expect(titles()).toEqual([t('roles.list.builtinTitle', { n: 4 }), t('roles.list.customTitle', { n: 1 })])
    await w.get('[data-test="role-pick"] input').setValue('資產')
    await flushPromises()
    expect(titles()).toEqual([t('roles.list.builtinTitle', { n: 1 })])
    expect(document.body.querySelectorAll('[data-test^="role-option-"]')).toHaveLength(1)
    await w.get('[data-test="role-pick"] input').setValue('')
    await flushPromises()
    expect(titles()).toEqual([t('roles.list.builtinTitle', { n: 4 }), t('roles.list.customTitle', { n: 1 })])
    w.unmount()
  })
})
