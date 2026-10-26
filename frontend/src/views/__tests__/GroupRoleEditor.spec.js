import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import GroupRoleEditor from '../usergroups/components/GroupRoleEditor.vue'
import { applyCurrentUser, resetCapabilities } from '@/composables/useCapabilities'
import i18n from '@/i18n'

enableAutoUnmount(afterEach)

const h = vi.hoisted(() => ({ request: vi.fn() }))
vi.mock('@/api/request', () => ({ default: (...a) => h.request(...a) }))

const t = (k, p) => i18n.global.t(k, p)

const defs = [
  { id: 3, name: 'user', builtin_key: 'user', scopable: true, node_range_no_effect: true, assignment_state: 'open', management_class: false, group_bindable: true },
  { id: 4, name: 'asset_admin', builtin_key: 'asset_admin', scopable: true, node_range_no_effect: false, assignment_state: 'open', management_class: true, group_bindable: true },
  { id: 5, name: 'security_admin', builtin_key: 'security_admin', scopable: false, node_range_no_effect: false, assignment_state: 'protected', management_class: true, group_bindable: true },
  { id: 6, name: 'auditor', builtin_key: 'auditor', scopable: false, node_range_no_effect: false, assignment_state: 'not_open', management_class: false, group_bindable: true },
  { id: 7, name: 'custom_solo', builtin_key: '', scopable: false, node_range_no_effect: false, assignment_state: 'open', management_class: false, group_bindable: false },
]
const NODES = [
  { id: 11, name: '甲節點', parent_id: null, depth: 1, path: '甲節點', subtree_asset_count: 12 },
  { id: 12, name: '乙節點', parent_id: null, depth: 1, path: '乙節點', subtree_asset_count: 6 },
]
const OPTIONS = {
  nodes: NODES,
  node_assignable_role_ids: [3, 4],
  node_range_no_effect_role_ids: [3],
  node_range_no_effect_reasons: { 3: 'builtin_global_only' },
}

const mountEditor = async (props = {}) => {
  const w = mount(GroupRoleEditor, {
    props: { definitions: defs, bindings: [], ...props },
    global: { plugins: [ElementPlus] },
  })
  await flushPromises()
  return w
}
const lastDraft = (w) => w.emitted('update:draft').at(-1)[0]
const calls = (method) => h.request.mock.calls.map((c) => c[0]).filter((c) => c.method.toUpperCase() === method)

beforeEach(() => {
  h.request.mockReset()
  resetCapabilities()
  i18n.global.locale.value = 'zh-TW'
  applyCurrentUser({ id: 1, permissions: ['usergroup:manage', 'role:assign'] })
  h.request.mockImplementation(async (c) => {
    if (c.method.toUpperCase() === 'GET' && c.url === '/role-assignment-options') return OPTIONS
    throw new Error(`unexpected request ${c.method} ${c.url}`)
  })
})

describe('角色與範圍編輯器：沒有群組的草稿模式', () => {
  it('bindings 為空時選資產管理員，輸出草稿只含該角色、不帶範圍，並標為新加入', async () => {
    const w = await mountEditor()
    w.vm.addPicked(4)
    await flushPromises()
    expect(lastDraft(w)).toEqual({ roleIds: [4], roleNodes: {} })
    expect(w.get('[data-test="group-role-asset_admin"]').text()).toContain(t('userDetail.roles.newlyAdded'))
  })

  it('再為它勾一個節點，roleNodes 的鍵是角色編號字串、值是節點陣列', async () => {
    const w = await mountEditor()
    w.vm.addPicked(4)
    await flushPromises()
    await w.get('[data-test="set-range-asset_admin"]').trigger('click')
    await w.get('[data-test="rnp-mode-nodes"] input').setValue(true)
    await w.get('[data-test="rnp-check-11"] input').setValue(true)
    await flushPromises()
    expect(lastDraft(w)).toEqual({ roleIds: [4], roleNodes: { 4: [11] } })
  })

  it('受保護、尚未開放、不能指派給群組的角色在選單停用並附與分頁相同的原因', async () => {
    const w = await mountEditor()
    const byName = Object.fromEntries(w.vm.roleOptions.map((o) => [o.name, o]))
    expect(byName.security_admin).toMatchObject({ disabled: true, reason: t('roles.assignState.protected') })
    expect(byName.auditor).toMatchObject({ disabled: true, reason: t('roles.assignState.notOpen') })
    expect(byName.custom_solo).toMatchObject({ disabled: true, reason: t('roles.assignState.notGroupBindable') })
    expect(byName.asset_admin.disabled).toBe(false)
  })

  it('台數為 null 時範圍面板底部不出現「暫時無法取得」', async () => {
    const w = await mountEditor({ roleAssets: null, countsUnavailable: false })
    w.vm.addPicked(4)
    await flushPromises()
    await w.get('[data-test="set-range-asset_admin"]').trigger('click')
    await w.get('[data-test="rnp-mode-nodes"] input').setValue(true)
    await flushPromises()
    expect(w.html()).not.toContain(t('roleNodePicker.countsUnavailable'))
    expect(w.get('[data-test="rnp-footer"]').text()).toBe('')
  })

  it('草稿模式只讀節點清單：預覽與任何寫入的呼叫數為 0', async () => {
    const w = await mountEditor()
    w.vm.addPicked(4)
    await flushPromises()
    await w.get('[data-test="set-range-asset_admin"]').trigger('click')
    await w.get('[data-test="rnp-mode-nodes"] input').setValue(true)
    await w.get('[data-test="rnp-check-12"] input').setValue(true)
    await flushPromises()
    const all = h.request.mock.calls.map((c) => c[0])
    expect(all.filter((c) => c.url === '/role-assignment-previews')).toHaveLength(0)
    for (const m of ['POST', 'PUT', 'PATCH', 'DELETE']) expect(calls(m)).toHaveLength(0)
  })
})
