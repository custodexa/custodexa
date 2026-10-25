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
  { id: 1, name: 'auditor', assignment_state: 'open', management_class: false },
  { id: 2, name: 'approver', assignment_state: 'open', management_class: false },
  { id: 3, name: 'asset_admin', assignment_state: 'open', management_class: true },
  { id: 4, name: 'user', assignment_state: 'open', management_class: false },
  { id: 5, name: 'duty_contact', assignment_state: 'open', management_class: false },
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
const open = async (w, role) => {
  await w.get(`[data-test="manual-role-${role}"]`).trigger('click')
  await flushPromises()
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
    expect(w.get('[data-test="tag-assignable-user"]').exists()).toBe(true)
    expect(w.get('[data-test="tag-no-range-auditor"]').text()).toBe(t('roleNodePicker.tagNoRange'))
    await open(w, 'auditor')
    expect(w.find('[data-test="range-panel"]').exists()).toBe(false)
    expect(w.find('[data-test="rnp-tree"]').exists()).toBe(false)
    // 內建角色在清單內：可切到指定節點並開出樹，指定節點時只出現內建角色說明
    await open(w, 'user')
    await setMode(w, 'nodes')
    expect(w.find('[data-test="rnp-tree"]').exists()).toBe(true)
    expect(w.text()).toContain(t('roleNodePicker.builtinGlobalOnlyNote'))
    expect(w.text()).not.toContain(t('roleNodePicker.rangeNoEffectNote'))
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
    // 切回全系統後提示消失
    await setMode(w, 'all')
    expect(w.find('[data-test="card-no-effect-duty_contact"]').exists()).toBe(false)
    expect(w.text()).not.toContain(t('roleNodePicker.rangeNoEffectNote'))
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
