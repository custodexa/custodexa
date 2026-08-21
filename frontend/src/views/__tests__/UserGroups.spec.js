import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import UserGroups from '../UserGroups.vue'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

// happy-dom 的 MutationObserver 與 el-table key-render-helper 不相容（同 MyConnections）
class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const getUserGroupsMock = vi.fn()
const createUserGroupMock = vi.fn()
const updateUserGroupMock = vi.fn()
const deleteUserGroupMock = vi.fn()
const replaceUserGroupMembersMock = vi.fn()
const getUserGroupAuthorizationCountMock = vi.fn()

vi.mock('@/api/userGroups', () => ({
  getUserGroups: (...a) => getUserGroupsMock(...a),
  createUserGroup: (...a) => createUserGroupMock(...a),
  updateUserGroup: (...a) => updateUserGroupMock(...a),
  deleteUserGroup: (...a) => deleteUserGroupMock(...a),
  replaceUserGroupMembers: (...a) => replaceUserGroupMembersMock(...a),
  getUserGroupAuthorizationCount: (...a) => getUserGroupAuthorizationCountMock(...a),
}))

vi.mock('@/api/auth', () => ({
  getUsers: vi.fn().mockResolvedValue({
    data: [
      { id: 1, username: 'alice' },
      { id: 2, username: 'bob' },
    ],
  }),
}))

const sampleGroups = {
  data: [
    {
      id: 1,
      name: 'ops',
      description: '維運',
      users: [{ id: 1, username: 'alice' }],
    },
    { id: 2, name: 'dev', description: '', users: [] },
  ],
  total: 2,
}

const mountView = () =>
  mount(UserGroups, {
    global: { plugins: [ElementPlus] },
  })

describe('UserGroups 使用者群組管理', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getUserGroupsMock.mockResolvedValue(sampleGroups)
  })

  it('列表渲染群組與成員 tag', async () => {
    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('ops')
    expect(text).toContain('alice')
    expect(text).toContain('dev')
    expect(text).toContain('無成員')
  })

  it('建立群組送出正確 payload 並刷新列表', async () => {
    createUserGroupMock.mockResolvedValue({ id: 3, name: 'sec' })
    const wrapper = mountView()
    await flushPromises()
    getUserGroupsMock.mockClear()

    wrapper.vm.openCreateDialog()
    await flushPromises()
    wrapper.vm.form.name = 'sec'
    wrapper.vm.form.description = '安全組'

    await wrapper.vm.submitForm()
    await flushPromises()

    expect(createUserGroupMock).toHaveBeenCalledWith({ name: 'sec', description: '安全組' })
    expect(wrapper.vm.formDialogVisible).toBe(false)
    expect(getUserGroupsMock).toHaveBeenCalled()
  })

  it('編輯群組走 update 分支', async () => {
    updateUserGroupMock.mockResolvedValue({ id: 1, name: 'ops-renamed' })
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openEditDialog({ id: 1, name: 'ops', description: '維運' })
    await flushPromises()
    wrapper.vm.form.name = 'ops-renamed'

    await wrapper.vm.submitForm()
    await flushPromises()

    expect(updateUserGroupMock).toHaveBeenCalledWith(1, {
      name: 'ops-renamed',
      description: '維運',
    })
  })

  it('成員全量替換（穿梭框語義）', async () => {
    replaceUserGroupMembersMock.mockResolvedValue({ id: 1, users: [] })
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openMembersDialog(sampleGroups.data[0])
    await flushPromises()
    // 預設帶入既有成員
    expect(wrapper.vm.memberIds).toEqual([1])

    wrapper.vm.memberIds = [1, 2]
    await wrapper.vm.submitMembers()
    await flushPromises()

    expect(replaceUserGroupMembersMock).toHaveBeenCalledWith(1, [1, 2])
    expect(wrapper.vm.membersDialogVisible).toBe(false)
  })

  it('建立失敗（重名 409）對話框保持開啟', async () => {
    createUserGroupMock.mockRejectedValue(new Error('使用者群組名稱已存在'))
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openCreateDialog()
    await flushPromises()
    wrapper.vm.form.name = 'ops'

    await wrapper.vm.submitForm()
    await flushPromises()

    expect(createUserGroupMock).toHaveBeenCalled()
    expect(wrapper.vm.formDialogVisible).toBe(true)
  })
})
