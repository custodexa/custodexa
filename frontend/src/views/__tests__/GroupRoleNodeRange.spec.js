import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import GroupRolesTab from '../usergroups/components/GroupRolesTab.vue'
import { ElDialogStub } from '@/__fixtures__/dialogStub'
import { applyCurrentUser, resetCapabilities } from '@/composables/useCapabilities'
import i18n from '@/i18n'

enableAutoUnmount(afterEach)

const h = vi.hoisted(() => ({ request: vi.fn() }))
vi.mock('@/api/request', () => ({ default: (...a) => h.request(...a) }))

const t = (k, p) => i18n.global.t(k, p)

const defs = [
  { id: 1, name: 'auditor', assignment_state: 'open', management_class: false, group_bindable: true },
  { id: 2, name: 'duty_contact', assignment_state: 'open', management_class: false, group_bindable: true },
  { id: 3, name: 'user', assignment_state: 'open', management_class: false, group_bindable: true },
  { id: 4, name: 'asset_admin', assignment_state: 'open', management_class: true, group_bindable: true },
]
const NODES = [
  { id: 11, name: '甲節點', parent_id: null, depth: 1, path: '甲節點', subtree_asset_count: 12 },
  { id: 12, name: '乙節點', parent_id: null, depth: 1, path: '乙節點', subtree_asset_count: 6 },
]
const noOp = { marks: [], self_direction: '', routes_gained: [], routes_lost: [], evaluated: 0 }
const basePreview = {
  total: 3,
  matched: 0,
  truncated: false,
  subjects: [],
  operation: noOp,
  group_assets: { before: 5, after: 17 },
  role_assets: [{ role_id: 4, total: 12 }],
}

let cfg
const setup = (over = {}) => {
  cfg = {
    options: {
      nodes: NODES,
      node_assignable_role_ids: [2, 3, 4],
      node_range_no_effect_role_ids: [2, 3],
      node_range_no_effect_reasons: { 2: 'no_scoped_permission', 3: 'builtin_global_only' },
    },
    preview: basePreview,
    putExtra: null,
    ...over,
  }
  h.request.mockImplementation(async (c) => {
    const key = `${c.method.toUpperCase()} ${c.url}`
    if (key === 'GET /role-assignment-options') return cfg.options
    if (key === 'POST /role-assignment-previews') return cfg.preview
    if (key === 'PUT /user-groups/1/role-bindings') return { data: [], ...(cfg.putExtra || {}) }
    throw new Error(`unexpected request ${key}`)
  })
}
const calls = (method, url) =>
  h.request.mock.calls.map((c) => c[0]).filter((c) => c.method.toUpperCase() === method && c.url === url)
const lastPut = () => calls('PUT', '/user-groups/1/role-bindings').pop()?.data

const mountTab = async (bindings) => {
  const w = mount(GroupRolesTab, {
    props: { group: { id: 1, name: 'SRE' }, bindings, definitions: defs },
    global: { plugins: [ElementPlus], stubs: { ElDialog: ElDialogStub } },
  })
  await flushPromises()
  return w
}
const wait = (ms) => new Promise((r) => setTimeout(r, ms))
const open = async (w, role) => {
  await w.get(`[data-test="group-role-${role}"]`).trigger('click')
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
const g = (role_id, role_name, extra = {}) => ({ role_id, role_name, scope: 'global', ...extra })

beforeEach(() => {
  h.request.mockReset()
  resetCapabilities()
  i18n.global.locale.value = 'zh-TW'
  applyCurrentUser({ id: 1, permissions: ['usergroup:manage', 'role:assign'] })
  setup()
})

describe('群組角色與範圍：節點範圍', () => {
  it('為可限定節點的角色勾甲後儲存：只為該角色帶節點，角色清單不變，底部與變化面板取自預覽', async () => {
    const w = await mountTab([g(4, 'asset_admin'), g(1, 'auditor')])
    expect(w.get('[data-test="tag-assignable-asset_admin"]').exists()).toBe(true)
    expect(w.get('[data-test="tag-no-range-auditor"]').exists()).toBe(true)
    await open(w, 'asset_admin')
    expect(w.get('[data-test="range-panel"] h4').exists()).toBe(true)
    await setMode(w, 'nodes')
    await pickNode(w, 11)
    await wait(500)
    await flushPromises()
    expect(w.get('[data-test="rnp-footer"]').text()).toBe(t('roleNodePicker.footerGroup', { nodes: 1, total: 12 }))
    expect(w.get('[data-test="impact-members"]').exists()).toBe(true)
    expect(w.get('[data-test="impact-group-assets"]').text()).toContain(
      t('roleNodePicker.changeAssetsValue', { after: 17, before: 5 })
    )
    expect(w.get('[data-test="impact-group-assets-note"]').text()).toBe(t('roleNodePicker.changeGroupAssetsNote'))
    const pv = calls('POST', '/role-assignment-previews').pop().data
    expect(pv.include_managed_asset_counts).toBe(true)
    expect(pv.role_nodes).toEqual({ 4: [11] })
    await save(w)
    expect(lastPut().role_ids).toEqual([4, 1])
    expect(lastPut().role_nodes).toEqual({ 4: [11] })
  })

  it('未改動範圍的角色與新加入且維持全系統的角色不帶 role_nodes', async () => {
    const w = await mountTab([g(4, 'asset_admin', { scope: 'nodes', node_ids: [11] }), g(3, 'user')])
    w.vm.addPicked(1)
    await flushPromises()
    await w.get('[data-test="remove-user"]').trigger('click')
    await save(w)
    expect(lastPut().role_ids).toEqual([4, 1])
    expect(lastPut().role_nodes).toBeUndefined()
  })

  it('以 scope 判讀節點範圍：node_ids 缺省的節點範圍列不讀成全系統', async () => {
    const w = await mountTab([g(4, 'asset_admin', { scope: 'nodes' }), g(3, 'user')])
    expect(w.find('[data-test="range-all-asset_admin"]').exists()).toBe(false)
    expect(w.get('[data-test="range-paths-asset_admin"]').exists()).toBe(true)
    expect(w.get('[data-test="nodes-empty-asset_admin"]').text()).toBe(t('apiError.VALIDATION_ROLE_BINDING_NODES_EMPTY'))
    await w.get('[data-test="remove-user"]').trigger('click')
    await save(w)
    expect(lastPut().role_nodes).toBeUndefined()
  })

  it('含失效節點：標示並可移除，儲存只帶有效節點', async () => {
    const w = await mountTab([g(4, 'asset_admin', { scope: 'nodes', node_ids: [11, 99] })])
    expect(w.get('[data-test="missing-note-asset_admin"]').text()).toBe(t('roleNodePicker.nodeMissingNote', { n: 1 }))
    expect(w.get('[data-test="group-role-asset_admin"]').text()).not.toContain('99')
    await w.get('[data-test="remove-missing-asset_admin"]').trigger('click')
    await flushPromises()
    expect(calls('PUT', '/user-groups/1/role-bindings')).toHaveLength(0)
    await save(w)
    expect(lastPut().role_nodes).toEqual({ 4: [11] })
  })

  it('範圍不會生效的角色勾甲後照常送出並依原因提示；寫入回應帶不生效清單時不出錯', async () => {
    setup({ putExtra: { node_range_no_effect: [{ role: '2', reason: 'no_scoped_permission' }] } })
    const w = await mountTab([g(2, 'duty_contact'), g(3, 'user')])
    await open(w, 'duty_contact')
    await setMode(w, 'nodes')
    await pickNode(w, 11)
    expect(w.get('[data-test="card-no-effect-duty_contact"]').text()).toBe(t('roleNodePicker.rangeNoEffectNote'))
    expect(w.text()).not.toContain(t('roleNodePicker.globalOnlyNote'))
    await open(w, 'user')
    await setMode(w, 'nodes')
    await pickNode(w, 12)
    expect(w.get('[data-test="card-no-effect-user"]').text()).toBe(t('roleNodePicker.builtinGlobalOnlyNote'))
    await save(w)
    expect(lastPut().role_nodes).toEqual({ 2: [11], 3: [12] })
    expect(w.emitted('changed')).toHaveLength(1)
  })
})
