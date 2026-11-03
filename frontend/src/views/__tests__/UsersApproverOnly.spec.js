import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Users from '../Users.vue'
import UserAccountForm from '../users/components/UserAccountForm.vue'
import { t } from '@/i18n'

// 使用者列表與建立帳號表單：只有審核者角色的標示與建立時的就近說明
const api = vi.hoisted(() => ({ list: vi.fn(), create: vi.fn(), push: vi.fn() }))
vi.mock('@/api/user', async (original) => ({
  ...(await original()),
  getUserList: api.list,
  createUser: api.create,
  checkSourcePolicy: vi.fn().mockResolvedValue({ allowed: true }),
  getUserDetail: vi.fn().mockResolvedValue({ data: {}, role_sets: { manual: [], mapped: [] } }),
  getRoleList: vi.fn().mockResolvedValue({ data: [{ name: 'admin' }, { name: 'user' }, { name: 'auditor' }, { name: 'approver' }] }),
}))
vi.mock('@/api/auth', () => ({ getCurrentUser: vi.fn().mockResolvedValue({ data: { id: 1 } }) }))
vi.mock('vue-router', () => ({
  useRoute: () => ({ params: {}, query: {} }),
  useRouter: () => ({ push: api.push, replace: vi.fn() }),
}))
class Observer { observe() {} disconnect() {} takeRecords() { return [] } }
vi.stubGlobal('MutationObserver', Observer)
enableAutoUnmount(afterEach)

const global = {
  plugins: [ElementPlus],
  stubs: {
    'el-dialog': { name: 'ElDialog', props: ['modelValue', 'title'], template: '<section v-if="modelValue"><h2>{{ title }}</h2><slot /><slot name="footer" /></section>' },
  },
}
const approverOnlyErr = { response: { status: 400, data: { error: 'x', code: 'VALIDATION_ROLE_SET_APPROVER_ONLY' } } }
const row = (id, username, over = {}) => ({ id, username, kind: 'human', active: true, roles: [{ name: 'approver' }], ...over })

beforeEach(() => {
  vi.clearAllMocks()
  api.list.mockResolvedValue({ data: [row(22, 'sun.yh', { approver_only: true }), row(24, 'lin.yt', { approver_only: false })], total: 2 })
})

describe('使用者列表：只有審核者角色的標籤', () => {
  it('approver_only 為 true 的列有標籤、false 的列沒有；點標籤到角色與範圍分頁', async () => {
    const w = mount(Users, { global })
    await flushPromises()
    const tags = w.findAll('[data-test="approver-only-tag"]')
    expect(tags).toHaveLength(1)
    expect(tags[0].text()).toBe(t('users.approverOnlyTag'))
    const rows = w.findAll('.el-table__body tr')
    expect(rows[0].find('[data-test="approver-only-tag"]').exists()).toBe(true)
    expect(rows[1].find('[data-test="approver-only-tag"]').exists()).toBe(false)
    // 測試環境的 transition 為 stub：點擊落在標籤本體
    await tags[0].get('.el-tag').trigger('click')
    expect(api.push).toHaveBeenCalledWith({ path: '/users/22', query: { tab: 'roles' } })
  }, 15000)
})

describe('建立帳號：只勾審核人員被擋', () => {
  const openFilled = async () => {
    const w = mount(Users, { global })
    await flushPromises()
    w.vm.handleCreate()
    await flushPromises()
    const vm = w.findComponent(UserAccountForm).vm
    Object.assign(vm.form, { username: 'sun.yh', password: 'Passw0rd!long', email: 'sun.yh@example.com', roles: ['approver'] })
    await flushPromises()
    return { w, vm }
  }

  it('收到碼：角色欄下方說明、對話框不關；按修正鈕以加上一般使用者的角色重送', async () => {
    api.create.mockRejectedValueOnce(approverOnlyErr).mockResolvedValueOnce({})
    const { w, vm } = await openFilled()
    await vm.handleSubmit()
    await flushPromises()
    const box = w.get('[data-test="create-approver-only"]')
    expect(box.text()).toContain(t('users.approverOnlyPrompt.createTitle'))
    expect(w.get('[data-test="user-dialog-submit"]').classes()).not.toContain('el-button--primary')
    expect(api.create).toHaveBeenCalledTimes(1)
    await w.get('[data-test="approver-only-fix"]').trigger('click')
    await flushPromises()
    expect(api.create).toHaveBeenCalledTimes(2)
    expect(api.create.mock.calls[1][0].roles).toEqual(['approver', 'user'])
    expect(w.find('[data-test="user-dialog-submit"]').exists()).toBe(false)
  }, 15000)

  it('不按修正鈕：沒有第二次請求；改勾選後說明收起', async () => {
    api.create.mockRejectedValueOnce(approverOnlyErr)
    const { w, vm } = await openFilled()
    await vm.handleSubmit()
    await flushPromises()
    expect(w.find('[data-test="create-approver-only"]').exists()).toBe(true)
    expect(api.create).toHaveBeenCalledTimes(1)
    vm.form.roles = ['approver', 'auditor']
    await flushPromises()
    expect(w.find('[data-test="create-approver-only"]').exists()).toBe(false)
    expect(api.create).toHaveBeenCalledTimes(1)
  }, 15000)
})
