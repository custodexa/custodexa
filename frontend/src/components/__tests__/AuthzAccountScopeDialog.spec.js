// 授權帳號範圍調整：預設 @ALL、可個別指定 username；
// ticket 來源列由伺服端 409 守門，前端就近呈現不吞錯。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import AuthzAccountScopeDialog from '../AuthzAccountScopeDialog.vue'
import { updateAuthorizationAccounts } from '@/api/authorizations'
import { getAssetList } from '@/api/assets'
import { listAssetAccounts } from '@/api/assetAccounts'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

vi.mock('@/api/authorizations', () => ({ updateAuthorizationAccounts: vi.fn() }))
vi.mock('@/api/assets', () => ({ getAssetList: vi.fn() }))
vi.mock('@/api/assetAccounts', () => ({ listAssetAccounts: vi.fn() }))

const dialogStub = {
  props: ['modelValue'],
  emits: ['open', 'update:modelValue'],
  mounted() {
    if (this.modelValue) this.$emit('open')
  },
  template: '<div v-if="modelValue" class="dialog-stub"><slot /><slot name="footer" /></div>',
}

const mountDialog = (row) =>
  mount(AuthzAccountScopeDialog, {
    props: { modelValue: true, row },
    global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub } },
  })

const assetRow = { id: 3, asset_id: 21, asset_name: 'web-01', accounts: ['@ALL'], source: 'manual' }

describe('AuthzAccountScopeDialog 帳號範圍', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    listAssetAccounts.mockResolvedValue({ data: [{ id: 1, username: 'root' }, { id: 2, username: 'app' }] })
    getAssetList.mockResolvedValue({ data: [] })
    updateAuthorizationAccounts.mockResolvedValue({})
  })

  it('既有 @ALL 開在「全部帳號」', async () => {
    const wrapper = mountDialog(assetRow)
    await flushPromises()
    expect(wrapper.vm.mode).toBe('all')
    expect(wrapper.vm.usernames).toEqual([])
  })

  it('既有具名清單開在「指定帳號」並回填', async () => {
    const wrapper = mountDialog({ ...assetRow, accounts: ['app', 'deploy'] })
    await flushPromises()
    expect(wrapper.vm.mode).toBe('named')
    expect(wrapper.vm.usernames).toEqual(['app', 'deploy'])
  })

  it('缺 accounts 欄視為全部帳號（未經序列化的路徑亦然）', async () => {
    const wrapper = mountDialog({ ...assetRow, accounts: undefined })
    await flushPromises()
    expect(wrapper.vm.mode).toBe('all')
  })

  it('資產客體的建議清單＝該資產帳號 username', async () => {
    const wrapper = mountDialog(assetRow)
    await flushPromises()
    expect(listAssetAccounts).toHaveBeenCalledWith(21, { skipErrorToast: true })
    expect(wrapper.vm.suggestions).toEqual(['app', 'root'])
  })

  it('節點客體的建議清單＝子樹內資產帳號的聯集（去重排序）', async () => {
    getAssetList.mockResolvedValue({ data: [{ id: 31 }, { id: 32 }] })
    listAssetAccounts
      .mockResolvedValueOnce({ data: [{ username: 'root' }, { username: 'app' }] })
      .mockResolvedValueOnce({ data: [{ username: 'app' }, { username: 'ops' }] })

    const wrapper = mountDialog({
      id: 4,
      asset_group_id: 8,
      asset_group_name: '生產節點',
      accounts: ['@ALL'],
      source: 'manual',
    })
    await flushPromises()

    expect(getAssetList).toHaveBeenCalledWith(
      expect.objectContaining({ node_id: 8, include_subtree: true })
    )
    expect(wrapper.vm.suggestions).toEqual(['app', 'ops', 'root'])
  })

  it('單一資產帳號查詢失敗不擋輸入（建議清單只是輸入輔助）', async () => {
    listAssetAccounts.mockRejectedValue(new Error('boom'))
    const wrapper = mountDialog(assetRow)
    await flushPromises()
    expect(wrapper.vm.suggestions).toEqual([])
  })

  it('送出「全部帳號」為顯式 ["@ALL"]（後端拒收空清單）', async () => {
    const wrapper = mountDialog(assetRow)
    await flushPromises()
    await wrapper.vm.handleSubmit()

    expect(updateAuthorizationAccounts).toHaveBeenCalledWith(3, ['@ALL'])
    expect(wrapper.emitted('saved')).toBeTruthy()
    expect(wrapper.emitted('update:modelValue').at(-1)).toEqual([false])
  })

  it('送出具名清單時去除空白項', async () => {
    const wrapper = mountDialog({ ...assetRow, accounts: ['app'] })
    await flushPromises()
    wrapper.vm.usernames = [' root ', '', 'app']
    await wrapper.vm.handleSubmit()

    expect(updateAuthorizationAccounts).toHaveBeenCalledWith(3, ['root', 'app'])
  })

  it('全空白輸入不得送出空陣列（disabled 條件與 payload 同源）', async () => {
    const wrapper = mountDialog({ ...assetRow, accounts: ['app'] })
    await flushPromises()
    wrapper.vm.usernames = ['   ', '']

    expect(wrapper.vm.trimmedUsernames).toEqual([])
    await wrapper.vm.handleSubmit()
    expect(updateAuthorizationAccounts).not.toHaveBeenCalled()
  })

  // allow-create 可打任何字串，`@ALL` 會被後端展開成全部帳號，
  // 畫面說「指定帳號」結果卻是「全部」，語義完全相反
  it('指定帳號模式擋下保留別名 @ALL，不得送出', async () => {
    const wrapper = mountDialog({ ...assetRow, accounts: ['app'] })
    await flushPromises()
    wrapper.vm.usernames = ['app', '@ALL']
    await flushPromises()

    expect(wrapper.vm.reservedUsernames).toEqual(['@ALL'])
    expect(wrapper.text()).toContain('保留別名')

    await wrapper.vm.handleSubmit()
    expect(updateAuthorizationAccounts).not.toHaveBeenCalled()

    // 移除保留值後恢復可送出
    wrapper.vm.usernames = ['app']
    await flushPromises()
    await wrapper.vm.handleSubmit()
    expect(updateAuthorizationAccounts).toHaveBeenCalledWith(3, ['app'])
  })

  it('任何 @ 開頭的輸入都擋（保留前綴，非只有 @ALL）', async () => {
    const wrapper = mountDialog({ ...assetRow, accounts: ['app'] })
    await flushPromises()
    wrapper.vm.usernames = ['@INPUT']
    await flushPromises()

    expect(wrapper.vm.reservedUsernames).toEqual(['@INPUT'])
    await wrapper.vm.handleSubmit()
    expect(updateAuthorizationAccounts).not.toHaveBeenCalled()
  })

  it('ticket 列的 409 就近呈現且對話框不關（伺服端二道防線）', async () => {
    const err = new Error('conflict')
    err.response = { status: 409, data: { code: 'CONFLICT_TICKET_ACCOUNT_SCOPE_IMMUTABLE' } }
    updateAuthorizationAccounts.mockRejectedValueOnce(err)

    const wrapper = mountDialog(assetRow)
    await flushPromises()
    await wrapper.vm.handleSubmit()
    await flushPromises()

    expect(wrapper.vm.submitError).toContain('臨時授權的帳號範圍由申請單決定')
    expect(wrapper.emitted('saved')).toBeFalsy()
    expect(wrapper.text()).toContain('臨時授權的帳號範圍由申請單決定')
  })
})
