import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import UserRoleScopeTab from '../components/UserRoleScopeTab.vue'
import { ElDialogStub } from '@/__fixtures__/dialogStub'
import { previewDisabledMapping, previewDirectCredentials } from '@/__fixtures__/rolePreviews'
import i18n from '@/i18n'

enableAutoUnmount(afterEach)

const h = vi.hoisted(() => ({ request: vi.fn(), push: vi.fn() }))

// 直接攔在 HTTP 層：驗證實際送出的路徑與本文鍵集合
vi.mock('@/api/request', () => ({ default: (...a) => h.request(...a) }))
vi.mock('vue-router', () => ({
  useRoute: () => ({ params: {}, query: {} }),
  useRouter: () => ({ push: h.push, replace: vi.fn() }),
}))

const t = (k, p) => i18n.global.t(k, p)
const err = (status, code) => ({ response: { status, data: code ? { error: { code } } : {} } })

const defs = [
  { id: 1, name: 'auditor', assignment_state: 'open', management_class: false },
  { id: 2, name: 'approver', assignment_state: 'open', management_class: false },
  { id: 3, name: 'security_admin', assignment_state: 'protected', management_class: true },
  { id: 4, name: 'asset_admin', assignment_state: 'not_open', management_class: true },
  { id: 5, name: 'cred_admin', assignment_state: 'open', management_class: true },
]
const noOp = { marks: [], self_direction: '', routes_gained: [], routes_lost: [], evaluated: 0 }
const noHit = { total: 0, matched: 0, truncated: false, subjects: [], operation: noOp }

let cfg
const setup = (over = {}) => {
  cfg = {
    defs,
    groups: { data: [{ id: 3, name: 'SRE', member_sources: [{ user_id: 9, manual: true, mapped: false }] }] },
    bindings: { data: [{ role_id: 1, role_name: 'auditor', scope: 'global' }] },
    userBindings: { data: [] },
    groupsError: null,
    preview: noHit,
    previewError: null,
    putError: null,
    putExtra: null,
    ...over,
  }
  h.request.mockImplementation(async (c) => {
    const key = `${c.method.toUpperCase()} ${c.url}`
    if (key === 'GET /role-definitions') return { data: cfg.defs, total: cfg.defs.length, can_define: false }
    if (key === 'GET /user-groups') {
      if (cfg.groupsError) throw cfg.groupsError
      return cfg.groups
    }
    if (key === 'GET /user-groups/3/role-bindings') return cfg.bindings
    if (key === 'GET /users/9/role-bindings') return cfg.userBindings
    if (key === 'POST /role-assignment-previews') {
      if (cfg.previewError) throw cfg.previewError
      return cfg.preview
    }
    if (key === 'PUT /users/9/roles') {
      if (cfg.putError) throw cfg.putError
      return { ...(cfg.putExtra || {}), role_sets: { manual: c.data.manual_roles, mapped: ['approver'] } }
    }
    if (key === 'POST /users/9/roles/pin') return { role_sets: { manual: ['auditor', c.data.role], mapped: [c.data.role] } }
    throw new Error(`unexpected request ${key}`)
  })
}
const calls = (method, url) =>
  h.request.mock.calls.map((c) => c[0]).filter((c) => c.method.toUpperCase() === method && c.url === url)

const mountTab = async (props = {}) => {
  const w = mount(UserRoleScopeTab, {
    props: { userId: 9, username: 'target', roleSets: { manual: ['auditor', 'approver'], mapped: [] }, ...props },
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

describe('UserRoleScopeTab：管理者指派', () => {
  it('下拉選項取自 GET /role-definitions；protected 與 not_open 停用並各有說明', async () => {
    const w = await mountTab()
    expect(calls('GET', '/role-definitions')).toHaveLength(1)
    const opts = Object.fromEntries(w.vm.roleOptions.map((o) => [o.name, o]))
    expect(Object.keys(opts)).toEqual(defs.map((d) => d.name))
    expect(opts.security_admin).toMatchObject({ disabled: true, reason: t('roles.assignState.protected') })
    expect(opts.asset_admin).toMatchObject({ disabled: true, reason: t('roles.assignState.notOpen') })
    expect(opts.cred_admin).toMatchObject({ disabled: false, reason: '' })
    expect(opts.auditor).toMatchObject({ disabled: true, reason: t('userDetail.roles.alreadyAdded') })
    const dom = w.findAll('.el-select-dropdown__item')
    const sec = dom.find((i) => i.text().includes(t('roles.assignState.protected')))
    const open = dom.find((i) => i.text().includes('cred_admin'))
    expect(sec.classes()).toContain('is-disabled')
    expect(open.classes()).not.toContain('is-disabled')
  })

  it('移除一個管理者指派角色後送出：本文鍵集合恰為 ["manual_roles"]，值只含剩餘者', async () => {
    const w = await mountTab()
    await w.get('[data-test="remove-approver"]').trigger('click')
    await w.get('[data-test="roles-save"]').trigger('click')
    await flushPromises()
    const puts = calls('PUT', '/users/9/roles')
    expect(puts).toHaveLength(1)
    expect(Object.keys(puts[0].data)).toEqual(['manual_roles'])
    expect(puts[0].data.manual_roles).toEqual(['auditor'])
    const pv = calls('POST', '/role-assignment-previews')
    expect(pv.length).toBeGreaterThan(0)
    expect(Object.keys(pv[pv.length - 1].data).sort()).toEqual(['kind', 'role_ids', 'user_id'])
    expect(w.emitted('changed')).toBeTruthy()
  })

  it('伺服器回 AUTH_PROTECTED_ROLE_ASSIGNMENT：顯示該碼譯文，角色清單不變', async () => {
    setup({ putError: err(403, 'AUTH_PROTECTED_ROLE_ASSIGNMENT') })
    const w = await mountTab()
    await w.get('[data-test="remove-approver"]').trigger('click')
    await w.get('[data-test="roles-save"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="assign-error"]').text()).toBe(t('apiError.AUTH_PROTECTED_ROLE_ASSIGNMENT'))
    expect(w.findAll('[data-test^="manual-role-"]').map((e) => e.attributes('data-test'))).toEqual([
      'manual-role-auditor',
      'manual-role-approver',
    ])
  })

  it('畫面不存在節點選擇元素，寫入本文沒有範圍欄位', async () => {
    const w = await mountTab()
    expect(w.find('.el-tree, [data-test*="node"], [data-test*="scope-pick"]').exists()).toBe(false)
    await w.get('[data-test="remove-approver"]').trigger('click')
    await w.get('[data-test="roles-save"]').trigger('click')
    await flushPromises()
    expect(JSON.stringify(calls('PUT', '/users/9/roles')[0].data)).not.toMatch(/scope|node/i)
  })
})

describe('UserRoleScopeTab：儲存前確認與變化面板', () => {
  it('預覽 subjects 為空但 operation.marks 含 management_grant：儲存前確認含會通知安全人員，確認後才送出', async () => {
    setup({ preview: previewDisabledMapping })
    const w = await mountTab()
    await w.get('[data-test="remove-approver"]').trigger('click')
    await w.get('[data-test="roles-save"]').trigger('click')
    await flushPromises()
    expect(calls('PUT', '/users/9/roles')).toHaveLength(0)
    const notify = w.get('[data-test="danger-notify"]')
    expect(notify.text()).toContain(t('dangerConfirm.notify.title'))
    await w.get('[data-test="danger-proceed"]').trigger('click')
    await flushPromises()
    expect(calls('PUT', '/users/9/roles')).toHaveLength(1)
  })

  it('預覽失敗：標示預覽暫時無法取得，不擋儲存（仍要儲存）', async () => {
    setup({ previewError: err(500, 'INTERNAL') })
    const w = await mountTab()
    await w.get('[data-test="remove-approver"]').trigger('click')
    await w.get('[data-test="roles-save"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="danger-preview-failed"]').exists()).toBe(true)
    expect(calls('PUT', '/users/9/roles')).toHaveLength(0)
    await w.get('[data-test="danger-proceed"]').trigger('click')
    await flushPromises()
    expect(calls('PUT', '/users/9/roles')).toHaveLength(1)
  })

  it('預覽回報對自己的方向（self_direction）：確認框顯示對自己權限變更的通知句', async () => {
    const selfPreview = { ...noHit, operation: { ...noOp, marks: ['management_grant'], self_direction: 'increase' } }
    setup({ preview: selfPreview })
    const w = await mountTab()
    await w.get('[data-test="remove-approver"]').trigger('click')
    await w.get('[data-test="roles-save"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="danger-notify"]').text()).toContain(t('dangerConfirm.notify.selfChange'))
    expect(calls('PUT', '/users/9/roles')).toHaveLength(0)
  })

  it('變化面板的新增與失去入口取自 operation.routes_*，不讀 entries_*；連線固定句含超管保留身分', async () => {
    setup({ preview: previewDirectCredentials })
    const w = await mountTab()
    await w.get('[data-test="remove-approver"]').trigger('click')
    await wait(500)
    await flushPromises()
    const gained = w.get('[data-test="routes-gained"]').text()
    const lost = w.get('[data-test="routes-lost"]').text()
    expect(gained).toContain(t('menu.credentials'))
    expect(gained).not.toContain('credentials.secret')
    expect(lost).toContain(t('menu.sessions'))
    expect(lost).not.toContain('assets')
    expect(w.get('[data-test="change-connection"]').text()).toContain('超級管理者另依既有的保留身分')
  })
})

describe('UserRoleScopeTab：映射與群組來源', () => {
  it('映射角色勾選觸發釘住一次，本文鍵恰為 ["role"]；保護角色的釘住停用', async () => {
    const w = await mountTab({ roleSets: { manual: ['auditor'], mapped: ['approver', 'security_admin'] } })
    expect(w.get('[data-test="pin-security_admin"] input').attributes('disabled')).toBeDefined()
    await w.get('[data-test="pin-approver"] input').setValue(true)
    await flushPromises()
    const pins = calls('POST', '/users/9/roles/pin')
    expect(pins).toHaveLength(1)
    expect(Object.keys(pins[0].data)).toEqual(['role'])
    expect(pins[0].data.role).toBe('approver')
  })

  it('來自映射區渲染映射時效說明恰一次；無政策讀取能力時為不帶數值的通則與收回補充句', async () => {
    const w = await mountTab({ roleSets: { manual: [], mapped: ['approver'] } })
    expect(w.findAll('[data-test="mapping-timing-notice"]')).toHaveLength(1)
    const text = w.get('[data-test="mapped-block"]').text()
    expect(text).toContain(t('identityGroupMappings.revalidation.unknown'))
    expect(text).toContain('儲存當下就收回這條規則給的權限')
    expect(text).not.toContain('映射的變更於下次登入時生效')
  })

  it('回應帶 role.mapped_ignored：提示改用釘住並列出被忽略的角色', async () => {
    document.querySelectorAll('.el-message').forEach((n) => n.remove()) // 清掉前面案例留下的訊息
    setup({ putExtra: { disclosures: [{ code: 'role.mapped_ignored', params: { roles: 'approver' } }] } })
    const w = await mountTab()
    await w.get('[data-test="remove-approver"]').trigger('click')
    await w.get('[data-test="roles-save"]').trigger('click')
    await flushPromises()
    expect(calls('PUT', '/users/9/roles')).toHaveLength(1)
    const msg = [...document.querySelectorAll('.el-message')].map((n) => n.textContent).join('|')
    expect(msg).toContain(t('users.mappedRolesIgnored', { roles: 'approver' }))
    expect(msg).not.toContain(t('users.rolesAssigned'))
  })

  it('觀測快照區：沒有快照顯示空說明；有快照列出通道、時間與每個群組原始值', async () => {
    const empty = await mountTab()
    expect(empty.get('[data-test="group-snapshot"]').text()).toContain(t('users.groupSnapshotEmpty'))
    const w = await mountTab({
      snapshot: { channel: 'oidc', groups: ['grp-a', 'grp-b'], at: '2026-10-01T08:00:00Z' },
    })
    const text = w.get('[data-test="group-snapshot"]').text()
    expect(text).toContain(t('users.groupSnapshotHint'))
    expect(text).toContain('oidc')
    expect(text).toContain('grp-a')
    expect(text).toContain('grp-b')
    expect(text).not.toContain(t('users.groupSnapshotEmpty'))
  })

  it('來自群組區唯讀：由 member_sources 與各群組 role-bindings 組成，無移除，連到群組角色頁', async () => {
    const w = await mountTab()
    const g = w.get('[data-test="group-3"]')
    expect(g.text()).toContain('SRE')
    expect(g.text()).toContain(t('enum.role.auditor.label'))
    expect(w.get('[data-test="group-block"]').findAll('button')).toHaveLength(0)
    await w.get('[data-test="group-link-3"]').trigger('click')
    expect(h.push).toHaveBeenCalledWith({ path: '/user-groups/3', query: { tab: 'roles' } })
  })

  it('讀取使用者群組回 403：該區顯示無權說明，另兩區照常', async () => {
    setup({ groupsError: err(403, 'AUTH_FORBIDDEN') })
    const w = await mountTab()
    expect(w.get('[data-test="group-unavailable"]').text()).toContain(t('userDetail.roles.groupUnavailable'))
    expect(w.find('[data-test="manual-block"]').exists()).toBe(true)
    expect(w.findAll('[data-test^="manual-role-"]')).toHaveLength(2)
    expect(w.find('[data-test="mapped-block"]').exists()).toBe(true)
  })
})
