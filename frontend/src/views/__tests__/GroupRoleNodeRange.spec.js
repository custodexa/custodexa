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
  { id: 1, name: 'auditor', builtin_key: 'auditor', scopable: false, node_range_no_effect: false, assignment_state: 'open', management_class: false, group_bindable: true },
  { id: 2, name: 'duty_contact', builtin_key: '', scopable: true, node_range_no_effect: true, assignment_state: 'open', management_class: false, group_bindable: true },
  { id: 3, name: 'user', builtin_key: 'user', scopable: true, node_range_no_effect: true, assignment_state: 'open', management_class: false, group_bindable: true },
  { id: 4, name: 'asset_admin', builtin_key: 'asset_admin', scopable: true, node_range_no_effect: false, assignment_state: 'open', management_class: true, group_bindable: true },
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
// 會生效的角色按「設定範圍」；範圍不會生效的角色經「更多」的「仍要限定節點」
const open = async (w, role) => {
  const btn = w.find(`[data-test="set-range-${role}"]`)
  if (btn.exists()) {
    await btn.trigger('click')
  } else {
    await w.get(`[data-test="more-${role}"]`).trigger('click')
    await w.get(`[data-test="still-limit-${role}"]`).trigger('click')
  }
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
    expect(w.get('[data-test="set-range-asset_admin"]').exists()).toBe(true)
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

// —— 3.8 分配角色選單、3.9 三欄管理範圍 ——
const bigDefs = () => {
  const d = [
    { id: 1, name: 'auditor', builtin_key: 'auditor', scopable: false, node_range_no_effect: false },
    { id: 2, name: 'builtin_x2', builtin_key: 'builtin_x2', scopable: false, node_range_no_effect: false },
    { id: 3, name: 'user', builtin_key: 'user', scopable: true, node_range_no_effect: true },
    { id: 4, name: 'asset_admin', builtin_key: 'asset_admin', scopable: true, node_range_no_effect: false },
    { id: 5, name: 'authz_admin', builtin_key: 'authz_admin', scopable: true, node_range_no_effect: false },
  ]
  for (let i = 6; i <= 8; i++) d.push({ id: i, name: `builtin_x${i}`, builtin_key: `builtin_x${i}`, scopable: false, node_range_no_effect: false })
  d.push({ id: 9, name: '資產盤點助理', builtin_key: '', scopable: true, node_range_no_effect: false })
  d.push({ id: 10, name: '唯讀助理', builtin_key: '', scopable: true, node_range_no_effect: true })
  for (let i = 11; i <= 24; i++) d.push({ id: i, name: `自訂角色${i}`, builtin_key: '', scopable: false, node_range_no_effect: false })
  return d.map((x) => ({ assignment_state: 'open', management_class: false, group_bindable: true, ...x }))
}
const mountBig = async (bindings = [], defsOver = bigDefs()) => {
  const el = document.createElement('div')
  document.body.appendChild(el)
  setup({
    options: {
      nodes: NODES,
      node_assignable_role_ids: [3, 4, 5, 9, 10],
      node_range_no_effect_role_ids: [3, 10],
      node_range_no_effect_reasons: { 3: 'builtin_global_only', 10: 'no_scoped_permission' },
    },
  })
  const w = mount(GroupRolesTab, {
    attachTo: el,
    props: { group: { id: 1, name: 'SRE' }, bindings, definitions: defsOver },
    global: { plugins: [ElementPlus], stubs: { ElDialog: ElDialogStub } },
  })
  await flushPromises()
  return w
}
const openSelect = async (w) => {
  await w.get('[data-test="role-pick"] .el-select__wrapper').trigger('click')
  await flushPromises()
}
const bodyOptions = () => [...document.body.querySelectorAll('[data-test^="role-option-"]')]

describe('群組角色與範圍：分配角色選單（3.8）', () => {
  it('選單掛在頁面層、可篩選、分內建與自訂兩組並標可限管理範圍', async () => {
    const w = await mountBig([])
    await openSelect(w)
    const root = w.get('[data-test="group-roles-tab"]').element
    const opts = bodyOptions()
    expect(opts.length).toBe(24)
    expect(opts.every((o) => !root.contains(o))).toBe(true)
    expect(opts.every((o) => document.body.contains(o))).toBe(true)
    const assetOpt = document.body.querySelector('[data-test="role-option-asset_admin"]')
    expect(assetOpt).not.toBeNull()
    expect(assetOpt.classList.contains('is-disabled')).toBe(false)
    const titles = [...document.body.querySelectorAll('.el-select-group__title')].map((e) => e.textContent.trim())
    expect(titles).toEqual([t('roles.list.builtinTitle', { n: 8 }), t('roles.list.customTitle', { n: 16 })])
    const tagged = (name) => document.body.querySelector(`[data-test="option-scopable-${name}"]`) !== null
    expect(tagged('asset_admin')).toBe(true)
    expect(tagged('authz_admin')).toBe(true)
    expect(tagged('資產盤點助理')).toBe(true)
    expect(tagged('user')).toBe(false)
    expect(tagged('auditor')).toBe(false)
    expect(tagged('唯讀助理')).toBe(false)
    expect(document.body.querySelector('.el-select-dropdown .el-select__filter, .el-select__input')).not.toBeNull()
    w.unmount()
  })

  it('輸入「資產」後可見選項只含名稱含「資產」者', async () => {
    const w = await mountBig([])
    await openSelect(w)
    const input = w.get('[data-test="role-pick"] input')
    await input.setValue('資產')
    await flushPromises()
    const visible = bodyOptions().filter((o) => o.offsetParent !== null || o.style.display !== 'none')
    const shown = visible.filter((o) => !o.closest('[style*="display: none"]')).map((o) => o.textContent)
    expect(shown.length).toBeGreaterThan(0)
    expect(shown.length).toBeLessThan(24)
    expect(shown.every((txt) => txt.includes('資產'))).toBe(true)
    expect(shown.some((txt) => txt.includes(roleLabelOf('asset_admin')))).toBe(true)
    w.unmount()
  })
})

const roleLabelOf = (n) => (n === 'asset_admin' ? t('enum.role.asset_admin.label') : n)

describe('群組角色與範圍：三欄管理範圍（3.9）', () => {
  const mountRows = (bindings, over = {}) => mountBig(bindings, bigDefs()).then((w) => {
    void over
    return w
  })

  it('(i) 資產管理員全系統：直接見全系統與說明，設定範圍展開與收合', async () => {
    const w = await mountRows([g(4, 'asset_admin')])
    const row = w.get('[data-test="group-role-asset_admin"]')
    expect(row.text()).toContain(t('roleNodePicker.modeAll'))
    expect(row.text()).toContain(t('roleNodePicker.scopeAllNote'))
    expect(w.find('[data-test="range-panel"]').exists()).toBe(false)
    const btn = w.get('[data-test="set-range-asset_admin"]')
    expect(btn.text()).toBe(t('roleNodePicker.setRange'))
    await btn.trigger('click')
    expect(w.get('[data-test="range-panel"]').exists()).toBe(true)
    expect(w.get('[data-test="range-panel"]').element.closest('tbody').contains(row.element)).toBe(true)
    expect(w.get('[data-test="set-range-asset_admin"]').text()).toBe(t('roleNodePicker.collapseRange'))
    await w.get('[data-test="set-range-asset_admin"]').trigger('click')
    expect(w.find('[data-test="range-panel"]').exists()).toBe(false)
    w.unmount()
  })

  it('(ii) 授權管理員兩個節點：未點列即見兩個路徑與台數', async () => {
    const w = await mountRows([g(5, 'authz_admin', { scope: 'nodes', node_ids: [11, 12] })])
    const txt = w.get('[data-test="range-paths-authz_admin"]').text()
    expect(txt).toContain('甲節點')
    expect(txt).toContain('乙節點')
    expect(txt).toContain(t('roleNodePicker.cardCount', { n: 12 }))
    expect(txt).toContain(t('roleNodePicker.cardCount', { n: 6 }))
    w.unmount()
  })

  it('(iii) 一般使用者全系統：不適用，更多內先說明再仍要限定節點，勾節點可儲存', async () => {
    const w = await mountRows([g(3, 'user')])
    const row = w.get('[data-test="group-role-user"]').text()
    expect(row).toContain(t('roles.list.scopeNotApplicable'))
    expect(row).toContain('以全系統指派')
    expect(row).not.toContain(t('roleNodePicker.tagScopable'))
    expect(w.find('[data-test="set-range-user"]').exists()).toBe(false)
    await w.get('[data-test="more-user"]').trigger('click')
    const panel = w.get('[data-test="more-panel-user"]').element
    expect(panel.textContent.indexOf(t('roleNodePicker.builtinGlobalOnlyNote'))).toBeGreaterThanOrEqual(0)
    expect(panel.textContent.indexOf(t('roleNodePicker.builtinGlobalOnlyNote'))).toBeLessThan(
      panel.textContent.indexOf(t('roleNodePicker.stillLimitNodes'))
    )
    await w.get('[data-test="still-limit-user"]').trigger('click')
    await flushPromises()
    await setMode(w, 'nodes')
    await pickNode(w, 11)
    expect(w.get('[data-test="roles-save"]').attributes('disabled')).toBeUndefined()
    await save(w)
    expect(calls('PUT', '/user-groups/1/role-bindings')).toHaveLength(1)
    expect(lastPut().role_nodes).toEqual({ 3: [11] })
    w.unmount()
  })

  it('(iv) 稽核人員：全系統與不需要選範圍，沒有設定範圍與更多', async () => {
    const w = await mountRows([g(1, 'auditor')])
    const row = w.get('[data-test="group-role-auditor"]').text()
    expect(row).toContain(t('roleNodePicker.modeAll'))
    expect(row).toContain(t('roleNodePicker.globalOnlyRowNote'))
    expect(w.find('[data-test="set-range-auditor"]').exists()).toBe(false)
    expect(w.find('[data-test="more-auditor"]').exists()).toBe(false)
    w.unmount()
  })

  it('(v) 權限不受節點限制的自訂角色全系統：寫不會生效，仍要限定節點在更多內', async () => {
    const w = await mountRows([g(10, '唯讀助理')])
    const row = w.get('[data-test="group-role-唯讀助理"]').text()
    expect(row).toContain(t('roleNodePicker.modeAll'))
    expect(row).toContain(t('roleNodePicker.rangeNoEffectNote'))
    expect(w.find('[data-test="set-range-唯讀助理"]').exists()).toBe(false)
    await w.get('[data-test="more-唯讀助理"]').trigger('click')
    expect(w.get('[data-test="more-panel-唯讀助理"]').text()).toContain(t('roleNodePicker.stillLimitNodes'))
    w.unmount()
  })

  it('在更多內按仍要限定節點後，焦點移到展開的範圍面板，不掉到頁面最外層', async () => {
    const w = await mountBig([g(10, '唯讀助理')])
    await w.get('[data-test="more-唯讀助理"]').trigger('click')
    w.get('[data-test="still-limit-唯讀助理"]').element.focus()
    await w.get('[data-test="still-limit-唯讀助理"]').trigger('click')
    await flushPromises()
    const panel = w.get('[data-test="range-panel"]').element
    expect(document.activeElement).toBe(panel)
  })

  it('(vi) 不能指派角色者：只見全系統或限定 N 個節點，沒有範圍按鈕，不讀指派選項', async () => {
    applyCurrentUser({ id: 1, permissions: ['usergroup:manage'] })
    const w = await mountRows([g(4, 'asset_admin', { scope: 'nodes', node_ids: [11, 12] }), g(5, 'authz_admin')])
    expect(w.get('[data-test="group-role-asset_admin"]').text()).toContain(t('roleNodePicker.nodeCountOnly', { n: 2 }))
    expect(w.get('[data-test="group-role-authz_admin"]').text()).toContain(t('roleNodePicker.modeAll'))
    expect(w.find('[data-test^="set-range-"]').exists()).toBe(false)
    expect(w.find('[data-test^="more-"]').exists()).toBe(false)
    expect(calls('GET', '/role-assignment-options')).toHaveLength(0)
    w.unmount()
  })

  it('(vii) 頂部說明含管理範圍說明與連線句，連結只在能進資產授權頁時出現並帶群組', async () => {
    const w = await mountRows([g(4, 'asset_admin')])
    const banner = w.get('[data-test="scope-banner"]').text()
    expect(banner).toContain(t('roleScope.bannerTitle'))
    expect(banner).toContain(t('roleScope.bannerBody'))
    expect(banner).toContain(t('userDetail.change.connectionFixed'))
    expect(banner).not.toContain('一律由資產授權決定')
    expect(w.find('[data-test="banner-go-authorizations"]').exists()).toBe(false)
    w.unmount()
    applyCurrentUser({ id: 1, permissions: ['usergroup:manage', 'role:assign', 'authorization:manage'] })
    const w2 = await mountRows([g(4, 'asset_admin')])
    await w2.get('[data-test="set-range-asset_admin"]').trigger('click')
    await setMode(w2, 'nodes')
    await pickNode(w2, 11)
    await wait(500)
    await flushPromises()
    expect(w2.get('[data-test="banner-go-authorizations"]').attributes('href')).toBe('/authorizations?user_group_id=1')
    expect(w2.get('[data-test="impact-go-authorizations"]').attributes('href')).toBe('/authorizations?user_group_id=1')
    expect(w2.get('[data-test="unsaved-asset_admin"]').exists()).toBe(true)
    w2.unmount()
  })
})

describe('群組儲存後的變化與選單篩選', () => {
  const titles = () => [...document.body.querySelectorAll('.el-select-group__title')].map((e) => e.textContent.trim())

  it('全系統持有可限範圍角色（含自訂角色，不看名稱）寫「全部資產」不寫 0 台', async () => {
    const w = await mountBig([g(9, '資產盤點助理')])
    cfg.preview = { ...basePreview, group_assets: { before: 0, after: 0 } }
    await w.vm.addPicked(1)
    await wait(500)
    await flushPromises()
    const row = w.get('[data-test="impact-group-assets"]')
    expect(w.get('[data-test="impact-group-assets-all"]').text()).toBe(t('roleNodePicker.changeAssetsAll'))
    expect(row.text()).toContain('全部資產')
    expect(row.text()).not.toContain('0 台')
    w.unmount()
  })

  it('沒有全系統可限範圍角色時仍寫台數', async () => {
    const w = await mountBig([g(3, 'user')])
    cfg.preview = { ...basePreview, group_assets: { before: 0, after: 0 } }
    await w.vm.addPicked(1)
    await wait(500)
    await flushPromises()
    expect(w.find('[data-test="impact-group-assets-all"]').exists()).toBe(false)
    expect(w.get('[data-test="impact-group-assets"]').text()).toContain(t('roleNodePicker.changeAssetsValue', { after: 0, before: 0 }))
    w.unmount()
  })

  it('篩選時兩組組標數字隨結果更新，清除篩選後還原', async () => {
    const w = await mountBig([])
    await openSelect(w)
    expect(titles()).toEqual([t('roles.list.builtinTitle', { n: 8 }), t('roles.list.customTitle', { n: 16 })])
    await w.get('[data-test="role-pick"] input').setValue('資產')
    await flushPromises()
    expect(titles()).toEqual([t('roles.list.builtinTitle', { n: 1 }), t('roles.list.customTitle', { n: 1 })])
    await w.get('[data-test="role-pick"] input').setValue('')
    await flushPromises()
    expect(titles()).toEqual([t('roles.list.builtinTitle', { n: 8 }), t('roles.list.customTitle', { n: 16 })])
    w.unmount()
  })
})
