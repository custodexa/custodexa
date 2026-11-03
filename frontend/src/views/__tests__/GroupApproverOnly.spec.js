import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import GroupRolesTab from '../usergroups/components/GroupRolesTab.vue'
import GroupRoleEditor from '../usergroups/components/GroupRoleEditor.vue'
import GroupMembersTab from '../usergroups/components/GroupMembersTab.vue'
import UserGroups from '../UserGroups.vue'
import { ElDialogStub } from '@/__fixtures__/dialogStub'
import { setCapabilitiesForTests, resetCapabilities } from '@/composables/useCapabilities'
import i18n from '@/i18n'

// 群組變更會讓成員只剩審核者角色：就近列出受影響成員、原樣重新檢查、群組角色可改回全系統
enableAutoUnmount(afterEach)

const h = vi.hoisted(() => ({ request: vi.fn() }))
vi.mock('@/api/request', () => ({ default: (...a) => h.request(...a) }))
vi.mock('@/api/auth', () => ({ getUsers: vi.fn().mockResolvedValue({ data: [] }) }))
vi.mock('vue-router', () => ({ useRouter: () => ({ push: vi.fn() }), useRoute: () => ({ params: {}, query: {} }) }))
class Observer { observe() {} disconnect() {} takeRecords() { return [] } }
vi.stubGlobal('MutationObserver', Observer)

const t = (k, p) => i18n.global.t(k, p)
const defs = [
  { id: 1, name: 'auditor', builtin_key: 'auditor', assignment_state: 'open', management_class: false, group_bindable: true },
  { id: 3, name: 'user', builtin_key: 'user', assignment_state: 'open', management_class: false, group_bindable: true },
  { id: 5, name: 'cred_admin', builtin_key: '', assignment_state: 'open', management_class: false, group_bindable: true },
]
const noOp = { marks: [], self_direction: '', routes_gained: [], routes_lost: [], evaluated: 0 }
const noHit = { total: 0, matched: 0, truncated: false, subjects: [], operation: noOp }
const people = (n) => Array.from({ length: n }, (_, i) => ({ id: 100 + i, username: `member${i}` }))
const blockedErr = (count, users) => ({
  response: {
    status: 400,
    data: { error: 'x', code: 'VALIDATION_USER_GROUP_APPROVER_ONLY_MEMBERS', params: { count }, details: { affected_users: users } },
  },
})
const SUN = { id: 12, username: 'sun.yh' }
const WU = { id: 15, username: 'wu.jh' }

// failures：寫入路徑 → 依序要丟出的錯誤（用完照常成功）；pending：寫入路徑 → 第 N 次（1 起算）改為等待中
let failures
let pending
const setup = () => {
  failures = {}
  pending = {}
  const seen = {}
  h.request.mockImplementation(async (c) => {
    const key = `${c.method.toUpperCase()} ${c.url}`
    seen[key] = (seen[key] || 0) + 1
    if (key === 'GET /role-assignment-options') {
      return { nodes: [{ id: 11, name: 'tp', path: 'tp' }], node_assignable_role_ids: [3, 5], node_range_no_effect_reasons: { 3: 'builtin_global_only' } }
    }
    if (key === 'POST /role-assignment-previews') return noHit
    if (pending[key] === seen[key]) return new Promise(() => {})
    if (failures[key]?.length) throw failures[key].shift()
    if (key === 'GET /user-groups') return { data: [{ id: 1, name: 'ops', users: [SUN], manual_user_ids: [12] }], total: 1 }
    if (key === 'GET /role-definitions') return { data: defs, total: defs.length }
    if (key === 'GET /user-groups/1/authorization-count') return { authorization_count: 0 }
    if (c.method.toUpperCase() === 'GET') return { data: [], total: 0 }
    return { data: [] }
  })
}
const calls = (method, url) =>
  h.request.mock.calls.map((c) => c[0]).filter((c) => c.method.toUpperCase() === method && c.url === url)
const global = { plugins: [ElementPlus], stubs: { ElDialog: ElDialogStub } }
const ROLES_PUT = 'PUT /user-groups/1/role-bindings'

const mountRoles = async (bindings = [{ role_id: 3, role_name: 'user', scope: 'global' }, { role_id: 1, role_name: 'auditor', scope: 'global' }]) => {
  const w = mount(GroupRolesTab, { props: { group: { id: 1, name: 'ops' }, bindings, definitions: defs }, global })
  await flushPromises()
  return w
}
const editorOf = (w) => w.findComponent(GroupRoleEditor).vm
const save = async (w) => {
  await w.get('[data-test="roles-save"]').trigger('click')
  await flushPromises()
}
const narrowUser = async (w) => {
  editorOf(w).setDraft(3, { mode: 'nodes', nodeIds: [11] })
  await flushPromises()
}

beforeEach(() => {
  h.request.mockReset()
  resetCapabilities()
  setCapabilitiesForTests(['usergroup:manage', 'role:assign', 'user:manage'])
  i18n.global.locale.value = 'zh-TW'
  setup()
})

describe('群組角色：會讓成員只剩審核者角色', () => {
  it('原因句含人數與每個帳號名；能進使用者管理時名字為新分頁連結', async () => {
    failures[ROLES_PUT] = [blockedErr(2, [SUN, WU])]
    const w = await mountRoles()
    await narrowUser(w)
    await save(w)
    const box = w.get('[data-test="group-approver-only"]')
    expect(box.get('[data-test="group-approver-only-reason"]').text()).toBe(t('userGroups.approverOnly.reasonSave', { count: 2 }))
    for (const u of [SUN, WU]) {
      const a = box.get(`[data-test="affected-user-${u.id}"]`)
      expect(a.element.tagName).toBe('A')
      expect(a.text()).toBe(u.username)
      expect(a.attributes('href')).toBe(`/users/${u.id}?tab=roles`)
      expect(a.attributes('target')).toBe('_blank')
      expect(a.attributes('rel')).toContain('noopener')
    }
    expect(box.text()).toContain(t('userGroups.approverOnly.listNote'))
    expect(w.get('[data-test="roles-save"]').classes()).not.toContain('el-button--primary')
  })

  it('不具使用者管理能力：名字為純文字、沒有 <a>', async () => {
    setCapabilitiesForTests(['usergroup:manage', 'role:assign'])
    failures[ROLES_PUT] = [blockedErr(2, [SUN, WU])]
    const w = await mountRoles()
    await narrowUser(w)
    await save(w)
    const box = w.get('[data-test="group-approver-only"]')
    expect(box.text()).toContain('sun.yh')
    expect(box.text()).toContain('wu.jh')
    expect(box.findAll('a')).toHaveLength(0)
    expect(box.text()).not.toContain(t('userGroups.approverOnly.listNote'))
  })

  it('人數 23、清單 20 筆：列出 20 個名字並寫「及其他 3 位」', async () => {
    failures[ROLES_PUT] = [blockedErr(23, people(20))]
    const w = await mountRoles()
    await narrowUser(w)
    await save(w)
    const box = w.get('[data-test="group-approver-only"]')
    expect(box.findAll('[data-test^="affected-user-"]')).toHaveLength(20)
    expect(box.get('[data-test="group-approver-only-more"]').text()).toContain('其他 3 位')
  })

  it('按「重新檢查並儲存」：第二次請求本文與第一次深相等；成功後錯誤消失', async () => {
    failures[ROLES_PUT] = [blockedErr(1, [SUN])]
    const w = await mountRoles()
    editorOf(w).addPicked(5)
    await narrowUser(w)
    await save(w)
    expect(calls('PUT', '/user-groups/1/role-bindings')).toHaveLength(1)
    await w.get('[data-test="group-approver-only-retry"]').trigger('click')
    await flushPromises()
    const puts = calls('PUT', '/user-groups/1/role-bindings')
    expect(puts).toHaveLength(2)
    expect(puts[1].data).toEqual(puts[0].data)
    expect(w.find('[data-test="group-approver-only"]').exists()).toBe(false)
    expect(w.emitted('changed')).toHaveLength(1)
  })

  it('錯誤顯示後改動草稿：錯誤區消失，回到一般儲存', async () => {
    failures[ROLES_PUT] = [blockedErr(1, [SUN])]
    const w = await mountRoles()
    await narrowUser(w)
    await save(w)
    expect(w.find('[data-test="group-approver-only"]').exists()).toBe(true)
    editorOf(w).addPicked(5)
    await flushPromises()
    expect(w.find('[data-test="group-approver-only"]').exists()).toBe(false)
    expect(w.get('[data-test="roles-save"]').classes()).toContain('el-button--primary')
  })

  it('一般使用者由全系統收窄：有「改回全系統」，按下後草稿的一般使用者回全系統、其餘不變、無新請求、錯誤區消失', async () => {
    failures[ROLES_PUT] = [blockedErr(1, [SUN])]
    const w = await mountRoles()
    editorOf(w).addPicked(5)
    await narrowUser(w)
    await save(w)
    const before = h.request.mock.calls.length
    const roleIdsBefore = [...editorOf(w).draft.roleIds]
    expect(w.get('[data-test="group-approver-only"]').text()).toContain(t('userGroups.approverOnly.revertNote'))
    // 主要「重新檢查並儲存」在前、次要「改回全系統」在後
    const order = w.findAll('.notice-actions [data-test^="group-approver-only-"]').map((b) => b.attributes('data-test'))
    expect(order).toEqual(['group-approver-only-retry', 'group-approver-only-revert'])
    expect(w.get('[data-test="group-approver-only-retry"]').classes()).toContain('el-button--primary')
    expect(w.get('[data-test="group-approver-only-revert"]').classes()).not.toContain('el-button--primary')
    await w.get('[data-test="group-approver-only-revert"]').trigger('click')
    await flushPromises()
    expect(editorOf(w).draftOf(3)).toEqual({ mode: 'all', nodeIds: [] })
    expect(editorOf(w).draft.roleNodes).toEqual({})
    expect(editorOf(w).draft.roleIds).toEqual(roleIdsBefore)
    expect(h.request.mock.calls.slice(before).filter((c) => c[0].method.toUpperCase() !== 'POST' || c[0].url !== '/role-assignment-previews')).toHaveLength(0)
    expect(w.find('[data-test="group-approver-only"]').exists()).toBe(false)
  })

  it('沒有收窄一般使用者（移除其他角色）：沒有「改回全系統」', async () => {
    failures[ROLES_PUT] = [blockedErr(1, [SUN])]
    const w = await mountRoles([{ role_id: 3, role_name: 'user', scope: 'global' }, { role_id: 5, role_name: 'cred_admin', scope: 'global' }])
    editorOf(w).addPicked(1)
    await flushPromises()
    await save(w)
    expect(w.find('[data-test="group-approver-only"]').exists()).toBe(true)
    expect(w.find('[data-test="group-approver-only-revert"]').exists()).toBe(false)
  })

  it('重送期間群組頁草稿未被重置', async () => {
    failures[ROLES_PUT] = [blockedErr(1, [SUN])]
    pending[ROLES_PUT] = 2
    const w = await mountRoles()
    editorOf(w).addPicked(5)
    await narrowUser(w)
    const draftBefore = JSON.parse(JSON.stringify(editorOf(w).draft))
    await save(w)
    await w.get('[data-test="group-approver-only-retry"]').trigger('click')
    await flushPromises()
    expect(calls('PUT', '/user-groups/1/role-bindings')).toHaveLength(2)
    expect(JSON.parse(JSON.stringify(editorOf(w).draft))).toEqual(draftBefore)
    expect(w.find('[data-test="group-approver-only"]').exists()).toBe(true)
  })
})

describe('成員維護與刪除群組：會讓成員只剩審核者角色', () => {
  it('成員分頁移出被擋：原因句為移出版；「重新檢查並儲存」第二次本文與第一次深相等', async () => {
    const MEMBERS_PUT = 'PUT /user-groups/1/members'
    failures[MEMBERS_PUT] = [blockedErr(1, [SUN])]
    const group = { id: 1, name: 'ops', users: [SUN, WU], manual_user_ids: [12, 15], mapped_user_ids: [], member_sources: [] }
    const w = mount(GroupMembersTab, { props: { group, users: [SUN, WU] }, global })
    await flushPromises()
    w.vm.manualIds = [15]
    await flushPromises()
    await w.get('[data-test="members-save"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="group-approver-only-reason"]').text()).toBe(t('userGroups.approverOnly.reasonRemove', { count: 1 }))
    await w.get('[data-test="group-approver-only-retry"]').trigger('click')
    await flushPromises()
    const puts = calls('PUT', '/user-groups/1/members')
    expect(puts).toHaveLength(2)
    expect(puts[1].data).toEqual(puts[0].data)
    expect(w.emitted('changed')).toHaveLength(1)
  })

  it('刪除群組被擋：對話框列出原因；「重新檢查並刪除」第二次為同一個 DELETE', async () => {
    const DEL = 'DELETE /user-groups/1'
    failures[DEL] = [blockedErr(6, [SUN, WU])]
    const { ElMessageBox } = await import('element-plus')
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const w = mount(UserGroups, { global })
    await flushPromises()
    await w.get('[data-test="delete-1"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="group-approver-only-reason"]').text()).toBe(t('userGroups.approverOnly.reasonDelete', { count: 6 }))
    expect(w.get('[data-test="group-approver-only-retry"]').text()).toBe(t('userGroups.approverOnly.retryDelete'))
    await w.get('[data-test="group-approver-only-retry"]').trigger('click')
    await flushPromises()
    const dels = calls('DELETE', '/user-groups/1')
    expect(dels).toHaveLength(2)
    expect(dels[1]).toEqual(dels[0])
    expect(w.find('[data-test="group-approver-only"]').exists()).toBe(false)
    confirmSpy.mockRestore()
  })
})
