import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import UserDetail from '../../UserDetail.vue'
import Users from '../../Users.vue'
import i18n from '@/i18n'
import { ElDialogStub } from '@/__fixtures__/dialogStub'
import router, { createAuthGuard } from '@/router/index'
import { resetSessionForTests, setAccessToken } from '@/utils/session'
import { meBody } from '@/composables/__tests__/capabilityFixtures'

enableAutoUnmount(afterEach)
class ObserverStub { observe() {} disconnect() {} takeRecords() { return [] } }
vi.stubGlobal('MutationObserver', ObserverStub)

const h = vi.hoisted(() => ({
  route: { params: { id: '9' }, query: {}, path: '/users/9' },
  push: vi.fn(),
  replace: vi.fn(),
  getUserDetail: vi.fn(),
  getUserList: vi.fn(),
  adminDisableMFA: vi.fn(),
  confirm: vi.fn(),
  me: vi.fn(),
  overview: vi.fn(),
}))

vi.mock('vue-router', async (orig) => ({
  ...(await orig()),
  useRoute: () => h.route,
  useRouter: () => ({ push: h.push, replace: h.replace }),
}))
vi.mock('@/api/auth', () => ({
  getCurrentUser: (...a) => h.me(...a),
  logout: vi.fn(),
}))
vi.mock('@/api/user', () => ({
  getUserDetail: (...a) => h.getUserDetail(...a),
  getUserList: (...a) => h.getUserList(...a),
  getRoleList: vi.fn().mockResolvedValue({ data: [] }),
  createUser: vi.fn(),
  updateUser: vi.fn(),
  deleteUser: vi.fn(),
  updateUserStatus: vi.fn(),
  changePassword: vi.fn(),
  adminDisableMFA: (...a) => h.adminDisableMFA(...a),
  unlockUser: vi.fn(),
  setInactivityExempt: vi.fn(),
  checkSourcePolicy: vi.fn(),
  pinUserRole: vi.fn(),
  assignRoles: vi.fn(),
  getExternalIdentities: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  bindExternalIdentity: vi.fn(),
  unbindExternalIdentity: vi.fn(),
  unbindExternalIdentityAndDisable: vi.fn(),
}))
vi.mock('@/api/permissionOverview', () => ({
  getPermissionOverview: (...a) => h.overview(...a),
  probePermissionAsset: vi.fn(),
  PROBE_NOT_FOUND: 'NOTFOUND_ASSET',
}))
vi.mock('@/api/roleDefinitions', () => ({ listRoleDefinitions: vi.fn().mockResolvedValue({ data: [] }) }))
vi.mock('@/api/assets', () => ({
  getAssetList: vi.fn().mockResolvedValue({ data: [] }),
  getAssetGroups: vi.fn().mockResolvedValue({ data: [] }),
}))
vi.mock('@/api/accessRequests', () => ({
  getApproverScopes: vi.fn().mockResolvedValue({ data: [] }),
  createApproverScope: vi.fn(),
  deleteApproverScope: vi.fn(),
}))
vi.mock('@/api/userGroups', () => ({
  getUserGroups: vi.fn().mockResolvedValue({ data: [] }),
  getUserGroupRoleBindings: vi.fn().mockResolvedValue({ data: [] }),
}))
vi.mock('@/api/oidc', () => ({ getOIDCProviders: vi.fn().mockResolvedValue({ data: [] }) }))
vi.mock('@/utils/confirm', () => ({ confirmDestructive: (...a) => h.confirm(...a) }))

const t = (k, p) => i18n.global.t(k, p)
const RolesTabStub = { name: 'UserRoleScopeTab', template: '<div data-test="roles-tab-stub" />' }
const global = {
  plugins: [ElementPlus],
  stubs: {
    'el-dialog': ElDialogStub,
    UserRoleScopeTab: RolesTabStub,
    RouterLink: { template: '<a><slot /></a>' },
    'router-link': { template: '<a><slot /></a>' },
  },
}

const ALL = (v) => ({
  set_password: v, disable_mfa: v, bind_identity: v, unbind_identity: v,
  unbind_and_disable: v, disable: v, enable: v, delete: v,
})
const base = (over = {}) => ({
  id: 9, username: 'target', email: 't@example.com', kind: 'human', active: true,
  totp_enabled: true, external_credential: false, provisioning_origin: 'local',
  auth_provider_names: [], roles: [{ name: 'user' }], ...over,
})
const detail = (user, ops) => ({
  data: user,
  role_sets: { manual: [], mapped: [] },
  ...(ops ? { account_ops: ops } : {}),
})
const mountDetail = async (user, ops, query = {}) => {
  h.route.query = query
  h.getUserDetail.mockResolvedValue(detail(user, ops))
  const w = mount(UserDetail, { global })
  await flushPromises()
  return w
}
const btn = (w, key) => w.find(`[data-test="account-op-btn-${key}"]`)
const reason = (w, key) => w.find(`[data-test="account-op-reason-${key}"]`).text()
const present = (w, key) => w.find(`[data-test="account-op-${key}"]`).exists()

beforeEach(() => {
  vi.clearAllMocks()
  i18n.global.locale.value = 'zh-TW'
  h.route.params = { id: '9' }
  h.route.query = {}
  h.confirm.mockResolvedValue('confirm')
  h.me.mockResolvedValue({ id: 1, username: 'admin' })
  h.getUserList.mockResolvedValue({ data: [], total: 0 })
})

describe('使用者詳情頁：分頁與入口', () => {
  it('依序是基本資料、角色與範圍、權限一覽三個分頁；預設在基本資料', async () => {
    const w = await mountDetail(base(), ALL('allowed'))
    const items = w.findAll('.el-tabs__item').map((i) => i.text())
    expect(items).toEqual([t('userDetail.tabs.basic'), t('userDetail.tabs.roles'), t('userDetail.tabs.permissions')])
    expect(h.overview).not.toHaveBeenCalled()
    expect(w.find('.el-tabs__item.is-active').text()).toBe(t('userDetail.tabs.basic'))
  })

  it('?tab=roles 直達第二分頁', async () => {
    const w = await mountDetail(base(), ALL('allowed'), { tab: 'roles' })
    expect(w.find('.el-tabs__item.is-active').text()).toBe(t('userDetail.tabs.roles'))
    expect(w.find('[data-test="roles-tab-stub"]').exists()).toBe(true)
  })

  it('?tab=permissions 直達第三分頁並呼叫一次權限一覽端點', async () => {
    h.overview.mockResolvedValue({
      user_id: 9, username: 'target',
      management: { identity: {}, sources: [], bindings: [], permissions: [], ineffective_sources: [] },
      connection: { available: false },
    })
    const w = await mountDetail(base(), ALL('allowed'), { tab: 'permissions' })
    expect(w.find('.el-tabs__item.is-active').text()).toBe(t('userDetail.tabs.permissions'))
    expect(w.find('[data-test="permission-overview-tab"]').exists()).toBe(true)
    expect(h.overview).toHaveBeenCalledTimes(1)
    expect(h.overview).toHaveBeenCalledWith(9)
  })

  it('權限一覽右上的使用者切換：導到新使用者的權限一覽；其他分頁沒有切換', async () => {
    h.overview.mockResolvedValue({
      user_id: 9, username: 'target',
      management: { identity: {}, sources: [], bindings: [], permissions: [], ineffective_sources: [] },
      connection: { available: false },
    })
    const w = await mountDetail(base(), ALL('allowed'), { tab: 'permissions' })
    const sw = w.findComponent({ name: 'PermissionOverviewUserSwitch' })
    expect(sw.exists()).toBe(true)
    sw.vm.$emit('switch', 12)
    expect(h.push).toHaveBeenCalledWith({ path: '/users/12', query: { tab: 'permissions' } })
    sw.vm.$emit('switch', 9)
    expect(h.push).toHaveBeenCalledTimes(1)

    const other = await mountDetail(base(), ALL('allowed'), { tab: 'roles' })
    expect(other.findComponent({ name: 'PermissionOverviewUserSwitch' }).exists()).toBe(false)
  })

  it('沒有 user:manage 時路由守衛拒絕，且詳情路由沿用使用者列表的入口規則', async () => {
    const guard = createAuthGuard()
    const next = vi.fn()
    const resolved = router.resolve('/users/9')
    expect(resolved.name).toBe('UserDetail')
    expect(resolved.meta).toEqual(router.resolve('/users').meta)
    resetSessionForTests()
    setAccessToken('abc')
    h.me.mockResolvedValue(meBody(['user']))
    await guard({ path: '/users/9', meta: resolved.meta }, { path: '/', meta: {} }, next)
    expect(next).toHaveBeenCalledWith('/dashboard')
    next.mockClear()
    resetSessionForTests()
    setAccessToken('abc')
    h.me.mockResolvedValue(meBody(['admin']))
    await guard({ path: '/users/9', meta: resolved.meta }, { path: '/', meta: {} }, next)
    expect(next).toHaveBeenCalledWith()
  })
})

describe('使用者詳情頁：保護分類疊加在既有條件上（逐鈕）', () => {
  it('已啟用 MFA 的本地超級管理者帳號、非超管操作者：六項為停用並附凍結鍵的說明', async () => {
    const ops = { ...ALL('super_only'), unbind_identity: 'allowed' }
    const w = await mountDetail(base(), ops)
    for (const key of ['set_password', 'disable_mfa', 'bind_identity']) {
      expect(btn(w, key).attributes('disabled'), key).toBeDefined()
      expect(reason(w, key)).toBe(t('userDetail.accountOps.blocked.superAccount'))
    }
    for (const key of ['disable', 'delete', 'unbind_and_disable']) {
      expect(btn(w, key).attributes('disabled'), key).toBeDefined()
      expect(reason(w, key)).toBe(t('userDetail.accountOps.blocked.lifecycleSuper'))
    }
    expect(btn(w, 'unbind_identity').attributes('disabled')).toBeUndefined()
    expect(w.find('[data-test="protected-super"]').exists()).toBe(true)
  })

  it('已啟用 MFA 的本地系統安全管理員帳號：四項可按且按下先提示、確認後才送出；停用類三項為停用', async () => {
    const ops = {
      set_password: 'notify', disable_mfa: 'notify', bind_identity: 'notify', unbind_identity: 'notify',
      unbind_and_disable: 'super_only', disable: 'super_only', enable: 'super_only', delete: 'super_only',
    }
    const w = await mountDetail(base(), ops)
    for (const key of ['set_password', 'disable_mfa', 'bind_identity', 'unbind_identity']) {
      expect(btn(w, key).attributes('disabled'), key).toBeUndefined()
      expect(w.find(`[data-test="account-op-notify-${key}"]`).exists(), key).toBe(true)
    }
    for (const key of ['disable', 'delete', 'unbind_and_disable']) {
      expect(btn(w, key).attributes('disabled'), key).toBeDefined()
      expect(reason(w, key)).toBe(t('userDetail.accountOps.blocked.lifecycleSecurity'))
    }
    expect(w.find('[data-test="protected-security"]').exists()).toBe(true)

    // 取消提示：不送出
    h.confirm.mockRejectedValueOnce('cancel')
    await btn(w, 'disable_mfa').trigger('click')
    await flushPromises()
    expect(h.confirm).toHaveBeenCalledTimes(1)
    expect(h.confirm.mock.calls[0][1]).toBe(t('userDetail.accountOps.notify.dialogTitle'))
    expect(h.adminDisableMFA).not.toHaveBeenCalled()

    // 確認提示（再確認既有的停用 MFA 確認框）後才送出
    h.confirm.mockClear()
    h.confirm.mockResolvedValue('confirm')
    await btn(w, 'disable_mfa').trigger('click')
    await flushPromises()
    expect(h.confirm.mock.calls[0][1]).toBe(t('userDetail.accountOps.notify.dialogTitle'))
    expect(h.adminDisableMFA).toHaveBeenCalledWith(9)
  })

  it('外部身分來源的超管帳號、超管操作者：無保護限制也無通知提示，設定密碼依外部帳號規則停用', async () => {
    const user = base({ totp_enabled: false, external_credential: true, provisioning_origin: 'oidc' })
    const w = await mountDetail(user, ALL('allowed'))
    expect(btn(w, 'set_password').attributes('disabled')).toBeDefined()
    expect(reason(w, 'set_password')).toBe(t('users.externalPasswordShort'))
    expect(present(w, 'disable_mfa')).toBe(false)
    for (const key of ['bind_identity', 'unbind_identity', 'unbind_and_disable', 'disable', 'delete']) {
      expect(btn(w, key).attributes('disabled'), key).toBeUndefined()
    }
    expect(w.findAll('[data-test^="account-op-notify-"]')).toHaveLength(0)
    expect(w.find('[data-test="protected-banner"]').exists()).toBe(false)
  })

  it('未啟用 MFA 的帳號：停用 MFA 不出現，不論保護分類', async () => {
    for (const v of ['allowed', 'notify', 'super_only']) {
      const w = await mountDetail(base({ totp_enabled: false }), ALL(v))
      expect(present(w, 'disable_mfa'), v).toBe(false)
    }
  })

  it('agent 目標：密碼與外部身分動作不出現', async () => {
    const w = await mountDetail(base({ kind: 'agent', totp_enabled: false }), ALL('allowed'))
    for (const key of ['set_password', 'disable_mfa', 'bind_identity', 'unbind_identity', 'unbind_and_disable']) {
      expect(present(w, key), key).toBe(false)
    }
    expect(present(w, 'delete')).toBe(true)
  })

  it('已停用的超管目標、非超管操作者：啟用為停用；解鎖照既有規則', async () => {
    const future = new Date(Date.now() + 3600e3).toISOString()
    const w = await mountDetail(base({ active: false, locked_until: future }), ALL('super_only'))
    expect(present(w, 'disable')).toBe(false)
    expect(btn(w, 'enable').attributes('disabled')).toBeDefined()
    expect(reason(w, 'enable')).toBe(t('userDetail.accountOps.blocked.lifecycleSuper'))
    expect(btn(w, 'unlock').attributes('disabled')).toBeUndefined()
    expect(present(w, 'unlock')).toBe(true)
  })
})

describe('使用者列表連到詳情頁', () => {
  beforeEach(() => {
    h.getUserList.mockResolvedValue({
      data: [{ id: 7, username: 'carol', active: true, kind: 'human', roles: [{ name: 'user' }] }],
      total: 1,
    })
  })

  it('使用者名稱連到 /users/:id', async () => {
    const w = mount(Users, { global })
    await flushPromises()
    await w.get('[data-test="user-link"]').trigger('click')
    expect(h.push).toHaveBeenCalledWith('/users/7')
  })

  it('「分配角色」導向 /users/:id?tab=roles，不再開對話框', async () => {
    document.body.innerHTML = ''
    const w = mount(Users, { global })
    await flushPromises()
    const item = Array.from(document.querySelectorAll('.el-dropdown-menu__item')).find((li) =>
      li.textContent.includes(t('users.assignRoles'))
    )
    expect(item).toBeDefined()
    item.click()
    await flushPromises()
    expect(h.push).toHaveBeenCalledWith({ path: '/users/7', query: { tab: 'roles' } })
    expect(w.vm.roleDialogVisible).toBeUndefined()
  })
})
