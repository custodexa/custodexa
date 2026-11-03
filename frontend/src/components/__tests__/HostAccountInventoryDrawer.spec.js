import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import HostAccountInventoryDrawer from '../asset/HostAccountInventoryDrawer.vue'
import previewWrite from '@/directives/previewWrite'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'

const getAssetMock = vi.fn()
const getHostKeyMock = vi.fn()
const listAccountsMock = vi.fn()
const getInvMock = vi.fn()
const startMock = vi.fn()
const reopenMock = vi.fn()
const ignoreMock = vi.fn()

vi.mock('@/api/assets', () => ({
  getAsset: (...a) => getAssetMock(...a),
  getAssetHostKey: (...a) => getHostKeyMock(...a),
}))
vi.mock('@/api/assetAccounts', () => ({ listAssetAccounts: (...a) => listAccountsMock(...a) }))
vi.mock('@/api/hostInventory', () => ({
  getAssetInventory: (...a) => getInvMock(...a),
  startInventoryScan: (...a) => startMock(...a),
  reopenInventoryFinding: (...a) => reopenMock(...a),
  ignoreInventoryFinding: (...a) => ignoreMock(...a),
}))

class ObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', ObserverStub)
vi.stubGlobal('ResizeObserver', ObserverStub)
enableAutoUnmount(afterEach)

const stubs = {
  'el-drawer': {
    props: ['modelValue'],
    template: '<div v-if="modelValue" class="drawer-stub"><slot name="header" /><slot /></div>',
  },
  'el-dialog': {
    props: ['modelValue'],
    template: '<div v-if="modelValue" class="dialog-stub"><slot /><slot name="footer" /></div>',
  },
  // 結果表的「重新開啟」仍用 popconfirm
  'el-popconfirm': {
    emits: ['confirm'],
    template:
      '<span><slot name="reference" /><button class="pc-confirm" @click="$emit(\'confirm\')" /></span>',
  },
  'el-popover': { template: '<span><slot name="reference" /><span class="pop-body"><slot /></span></span>' },
  'el-tooltip': { template: '<span><slot /></span>' },
  'el-collapse': { template: '<div class="collapse-stub"><slot /></div>', props: ['modelValue'] },
  'el-collapse-item': { template: '<div class="collapse-item-stub"><slot /></div>', props: ['title', 'name'] },
}

const ASSET = { id: 7, name: 'web-01', host: '10.0.0.7', protocol: 'ssh', effective_rotation_channel: 'posix_ssh' }
const ACCOUNTS = { data: [{ id: 1, username: 'testuser', is_default: true }] }
const SCAN = {
  id: 5, status: 'succeeded', identity_mode: 'default_account', initiated_by_name: 'alice',
  started_at: '2026-11-02T10:00:00Z', finished_at: '2026-11-02T10:00:20Z',
  accounts_total: 12, privileged_total: 3, unmanaged_privileged_total: 2, privileged_groups: 'root,sudo',
}
const finding = (o = {}) => ({
  id: 1, asset_id: 7, username: 'deploy', uid: '1001', uid_conflict: false, login_capable: true,
  privileged: true, incomplete: false, present: true, managed: false,
  privileged_reasons: ['group:sudo'], status: 'open', ...o,
})
const inv = (o = {}) => ({
  scan: SCAN, coverage: [], fixed_notes: ['other_escalation_tools'], findings: [finding()],
  total: 1, page: 1, page_size: 50, ...o,
})
const apiErr = (status, code) => Object.assign(new Error('x'), { response: { status, data: code ? { code } : {} } })

async function open(props = {}, perms = ['asset:view', 'account:discover', 'asset:update']) {
  setCapabilitiesForTests(perms)
  const w = mount(HostAccountInventoryDrawer, {
    props: { modelValue: true, assetId: 7, ...props },
    global: { plugins: [ElementPlus], stubs, directives: { 'preview-write': previewWrite } },
  })
  await flushPromises()
  return w
}

beforeEach(() => {
  vi.clearAllMocks()
  getAssetMock.mockResolvedValue({ ...ASSET })
  getHostKeyMock.mockResolvedValue({ fingerprint: 'SHA256:x' })
  listAccountsMock.mockResolvedValue(ACCOUNTS)
  getInvMock.mockResolvedValue(inv())
})
afterEach(() => {
  vi.useRealTimers()
  resetCapabilities()
})

describe('盤點抽屜：狀態', () => {
  it('只收資產識別，開啟時以 getAsset 取詳情與旗標', async () => {
    const w = await open()
    expect(getAssetMock).toHaveBeenCalledWith(7, expect.anything())
    expect(w.find('[data-test="inv-subtitle"]').text()).toContain('web-01')
  })

  it('從未盤點：說明卡；有權者有開始鈕', async () => {
    getInvMock.mockResolvedValue(inv({ scan: null, findings: [], total: 0, coverage: [] }))
    const w = await open()
    expect(w.find('[data-test="inv-never"]').exists()).toBe(true)
    expect(w.find('[data-test="inv-start"]').attributes('disabled')).toBeUndefined()
    expect(w.find('[data-test="inv-table"]').exists()).toBe(false)
  })

  it('從未盤點、唯讀者：沒有開始鈕，說明需要權限', async () => {
    getInvMock.mockResolvedValue(inv({ scan: null, findings: [], total: 0 }))
    const w = await open({}, ['asset:view'])
    expect(w.find('[data-test="inv-start"]').exists()).toBe(false)
    expect(w.find('[data-test="inv-never-readonly"]').exists()).toBe(true)
    expect(w.find('[data-test="inv-readonly"]').exists()).toBe(true)
  })

  it('沒有預設帳號：以 is_default 判斷，開始鈕停用', async () => {
    listAccountsMock.mockResolvedValue({ data: [{ id: 2, username: 'testuser', is_default: false }] })
    getInvMock.mockResolvedValue(inv({ scan: null, findings: [], total: 0 }))
    const w = await open()
    expect(w.find('[data-test="inv-start"]').attributes('disabled')).toBeDefined()
  })

  it('預設帳號名缺席時確認氣泡用退路文字', async () => {
    listAccountsMock.mockResolvedValue({ data: [{ id: 2, is_default: true }] })
    getInvMock.mockResolvedValue(inv({ scan: null, findings: [], total: 0 }))
    const w = await open()
    expect(w.get('[data-test="inv-confirm-title"]').text()).toContain('這台的預設帳號')
    expect(w.find('[data-test="inv-start"]').exists()).toBe(true)
  })

  it('旗標不允許時（範圍化檢視者）開始鈕停用但抽屜可開', async () => {
    getAssetMock.mockResolvedValue({ ...ASSET, actions: { discover_accounts: { allowed: false, reason: 'out_of_scope' } } })
    getInvMock.mockResolvedValue(inv({ scan: null, findings: [], total: 0 }))
    const w = await open()
    expect(w.find('[data-test="inv-start"]').exists()).toBe(false)
    expect(w.find('[data-test="inv-never"]').exists()).toBe(true)
  })

  it('發起 202 後轉等待中，輪詢 queued、running、succeeded 後停止', async () => {
    vi.useFakeTimers()
    getInvMock.mockResolvedValue(inv({ scan: null, findings: [], total: 0 }))
    const w = await open()
    startMock.mockResolvedValue({ id: 6, status: 'queued', identity_mode: 'default_account' })
    getInvMock.mockResolvedValueOnce(inv({ scan: { ...SCAN, status: 'running' } }))
    getInvMock.mockResolvedValueOnce(inv({ scan: { ...SCAN, status: 'succeeded' } }))
    await w.find('[data-test="inv-confirm-ok"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="inv-status-text"]').text()).toContain('等待中')
    await vi.advanceTimersByTimeAsync(3000)
    expect(w.find('[data-test="inv-status-text"]').text()).toContain('盤點中')
    await vi.advanceTimersByTimeAsync(3000)
    expect(w.find('[data-test="inv-status-text"]').text()).toContain('完成')
    const calls = getInvMock.mock.calls.length
    await vi.advanceTimersByTimeAsync(9000)
    expect(getInvMock.mock.calls.length).toBe(calls)
  })

  it('120 秒仍在進行：停止輪詢並出現重新整理', async () => {
    vi.useFakeTimers()
    getInvMock.mockResolvedValue(inv({ scan: { ...SCAN, status: 'running' } }))
    const w = await open()
    await vi.advanceTimersByTimeAsync(123000)
    expect(w.find('[data-test="inv-poll-timeout"]').exists()).toBe(true)
    const calls = getInvMock.mock.calls.length
    await vi.advanceTimersByTimeAsync(9000)
    expect(getInvMock.mock.calls.length).toBe(calls)
  })

  it('輪詢途中讀取失敗：停止並出現重試，結果保留', async () => {
    vi.useFakeTimers()
    getInvMock.mockResolvedValue(inv({ scan: { ...SCAN, status: 'running' } }))
    const w = await open()
    getInvMock.mockRejectedValueOnce(apiErr(500))
    await vi.advanceTimersByTimeAsync(3000)
    expect(w.find('[data-test="inv-poll-failed"]').exists()).toBe(true)
    expect(w.findAll('[data-test="inv-row"]').length).toBe(1)
    const calls = getInvMock.mock.calls.length
    await vi.advanceTimersByTimeAsync(9000)
    expect(getInvMock.mock.calls.length).toBe(calls)
  })

  it('關閉抽屜後沒有後續請求', async () => {
    vi.useFakeTimers()
    getInvMock.mockResolvedValue(inv({ scan: { ...SCAN, status: 'running' } }))
    const w = await open()
    await w.setProps({ modelValue: false })
    const calls = getInvMock.mock.calls.length
    await vi.advanceTimersByTimeAsync(15000)
    expect(getInvMock.mock.calls.length).toBe(calls)
  })
})

describe('盤點抽屜：盤點未完成時不給結論', () => {
  it('第一次盤點、等待中：主體是骨架列，沒有數字、篩選與空狀態；狀態卡寫這次的時間與身分', async () => {
    getInvMock.mockResolvedValue(inv({ scan: null, findings: [], total: 0 }))
    const w = await open()
    startMock.mockResolvedValue({
      id: 6, status: 'queued', identity_mode: 'default_account', initiated_by_name: 'admin',
      created_at: '2026-11-03T08:00:00Z', accounts_total: 0, privileged_total: 0, unmanaged_privileged_total: 0,
    })
    await w.find('[data-test="inv-confirm-ok"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="inv-skeleton"]').exists()).toBe(true)
    expect(w.find('[data-test="inv-count-unmanaged"]').exists()).toBe(false)
    expect(w.find('[data-test="inv-filters"]').exists()).toBe(false)
    expect(w.find('[data-test="inv-empty"]').exists()).toBe(false)
    expect(w.text()).not.toContain('沒有需要處理的帳號')
    expect(w.find('[data-test="inv-coverage"]').exists()).toBe(false)
    const meta = w.find('[data-test="inv-lastrun"]').text()
    expect(meta).toMatch(/^這次：/)
    expect(meta).toContain('admin')
    expect(meta).toContain('用預設帳號 testuser 登入')
  })

  it('抽屜在第一次盤點進行中開啟（沒有先前結果）：同樣只有骨架列', async () => {
    getInvMock.mockResolvedValue(inv({ scan: { ...SCAN, status: 'running', accounts_total: 0, privileged_total: 0, unmanaged_privileged_total: 0 }, findings: [], total: 0 }))
    const w = await open()
    expect(w.find('[data-test="inv-skeleton"]').exists()).toBe(true)
    expect(w.find('[data-test="inv-empty"]').exists()).toBe(false)
    expect(w.find('[data-test="inv-count-unmanaged"]').exists()).toBe(false)
  })

  it('重新盤點中：顯示上一次的結果（時間），數字取上一次，不是這次的 0', async () => {
    const w = await open()
    startMock.mockResolvedValue({
      id: 6, status: 'queued', identity_mode: 'default_account', initiated_by_name: 'admin',
      created_at: '2026-11-03T08:00:00Z', accounts_total: 0, privileged_total: 0, unmanaged_privileged_total: 0,
    })
    await w.find('[data-test="inv-confirm-ok"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="inv-skeleton"]').exists()).toBe(false)
    expect(w.find('[data-test="inv-prev"]').text()).toMatch(/^上一次的結果（.+）$/)
    expect(w.find('[data-test="inv-count-unmanaged"]').text()).toContain('2')
    expect(w.find('[data-test="inv-filter-needs"]').text()).toContain('（2）')
    expect(w.find('[data-test="inv-lastrun"]').text()).toMatch(/^這次：/)
  })

  it('第一次盤點就失敗：不顯示 0 個帳號與「沒有需要處理」', async () => {
    getInvMock.mockResolvedValue(
      inv({ scan: { ...SCAN, status: 'failed', failure_reason: 'INVENTORY_LOGIN_FAILED', accounts_total: 0 }, findings: [], total: 0 })
    )
    const w = await open()
    expect(w.find('[data-test="inv-banner-failed"]').exists()).toBe(true)
    expect(w.find('[data-test="inv-count-unmanaged"]').exists()).toBe(false)
    expect(w.find('[data-test="inv-empty"]').exists()).toBe(false)
  })
})

describe('盤點抽屜：結果', () => {
  it('完成：三個數字與表格', async () => {
    const w = await open()
    expect(w.find('[data-test="inv-status-text"]').text()).toContain('共 12 個帳號')
    expect(w.find('[data-test="inv-count-unmanaged"]').text()).toContain('2')
    // 第三張卡與「需要處理」頁籤同義（數字已排除系統預設帳號）
    expect(w.find('[data-test="inv-count-unmanaged"]').text()).toContain('需要處理的特權帳號（點一下只看這些）')
    expect(w.find('[data-test="inv-count-unmanaged"]').text()).not.toContain('尚未納管')
    expect(w.findAll('[data-test="inv-row"]').length).toBe(1)
  })

  it('部分完成：警示列出缺項與後果，檢查範圍列出各項', async () => {
    getInvMock.mockResolvedValue(
      inv({
        scan: { ...SCAN, status: 'partial' },
        coverage: [
          { check: 'accounts', state: 'checked', count: 12 },
          { check: 'sudoers_main', state: 'unreadable', reason: 'permission_denied', count: 0 },
        ],
      })
    )
    const w = await open()
    const banner = w.find('[data-test="inv-banner-partial"]')
    expect(banner.text()).toContain('讀不到 sudo 規則（/etc/sudoers）：登入帳號沒有讀取權限')
    expect(banner.text()).toContain('實際權限可能比這裡顯示的更高')
    expect(w.findAll('[data-test="cov-item"]').length).toBe(2)
  })

  it('部分完成：標題是摘要句、登入身分說明沒有專用帳號、檢查範圍帶路徑、主規則檔讀不到時無法判斷', async () => {
    getInvMock.mockResolvedValue(
      inv({
        scan: { ...SCAN, status: 'partial', accounts_total: 21, privileged_total: 5, unmanaged_privileged_total: 4 },
        coverage: [
          { check: 'accounts', state: 'checked', count: 21 },
          { check: 'sudoers_main', state: 'unreadable', reason: 'permission_denied', count: 0 },
          { check: 'sudoers_dir', state: 'unreadable', reason: 'permission_denied', count: 0 },
          { check: 'sudoers_unresolved', state: 'undetermined', count: 0 },
        ],
      })
    )
    const w = await open()
    expect(w.find('[data-test="inv-status-tag"]').text()).toContain('部分完成：結果可能不完整')
    const title = w.find('[data-test="inv-status-text"]').text()
    expect(title).toBe('共 21 個帳號，5 個特權帳號，其中 4 個需要處理。')
    expect(w.find('[data-test="inv-lastrun"]').text()).toContain(
      '用預設帳號 testuser 登入（這台沒有設定堡壘機專用帳號，部分設定可能讀不到）'
    )
    expect(w.find('[data-test="inv-banner-partial"]').text()).toContain('（/etc/sudoers.d）')
    const cov = w.findAll('[data-test="cov-item"]').map((c) => c.text())
    expect(cov[1]).toContain('sudo 主規則檔（/etc/sudoers）')
    expect(cov[2]).toContain('sudo 規則目錄（/etc/sudoers.d）')
    expect(cov[3]).toContain('主規則檔讀不到，無法判斷')
    expect(cov[3]).not.toContain('已檢查')
  })

  it('檢查範圍：主規則檔讀得到時，無法解析的項目照後端狀態顯示；回應帶路徑時用回應值', async () => {
    getInvMock.mockResolvedValue(
      inv({
        coverage: [
          { check: 'sudoers_main', state: 'checked', count: 1, path: '/usr/local/etc/sudoers' },
          { check: 'sudoers_unresolved', state: 'checked', count: 0 },
        ],
      })
    )
    const w = await open()
    const cov = w.findAll('[data-test="cov-item"]').map((c) => c.text())
    expect(cov[0]).toContain('（/usr/local/etc/sudoers）')
    expect(cov[1]).toContain('已檢查')
    expect(cov[1]).not.toContain('無法判斷')
  })

  it('第三張數字卡提示可點，點了切到需要處理', async () => {
    const w = await open()
    await w.find('[data-test="inv-filter-ignored"] input').setValue()
    await flushPromises()
    const card = w.find('[data-test="inv-count-unmanaged"]')
    expect(card.text()).toContain('（點一下只看這些）')
    await card.trigger('click')
    await flushPromises()
    expect(getInvMock.mock.calls.at(-1)[1]).toMatchObject({ privileged: true, managed: false, present: true, status: 'open', actionable: true })
  })

  it('失敗：原因碼白話與下一步，下方保留上一次的結果', async () => {
    getInvMock.mockResolvedValue(
      inv({ scan: { ...SCAN, status: 'failed', failure_reason: 'INVENTORY_HOST_KEY_MISMATCH' } })
    )
    const w = await open()
    expect(w.find('[data-test="inv-banner-failed"]').text()).toContain('身分指紋和記錄不同')
    expect(w.find('[data-test="inv-go-hostkey"]').exists()).toBe(true)
    expect(w.find('[data-test="inv-prev"]').exists()).toBe(true)
    expect(w.findAll('[data-test="inv-row"]').length).toBe(1)
  })

  it('失敗但無編輯權：只有文字，沒有前往鈕', async () => {
    getAssetMock.mockResolvedValue({ ...ASSET, actions: { edit: { allowed: false }, discover_accounts: { allowed: true } } })
    getInvMock.mockResolvedValue(
      inv({ scan: { ...SCAN, status: 'failed', failure_reason: 'INVENTORY_HOST_KEY_MISMATCH' } })
    )
    const w = await open()
    expect(w.find('[data-test="inv-go-hostkey"]').exists()).toBe(false)
  })

  it('失敗：未知原因碼顯示通用說明與原碼', async () => {
    getInvMock.mockResolvedValue(
      inv({ scan: { ...SCAN, status: 'failed', failure_reason: 'INVENTORY_NEW_ONE' } })
    )
    const w = await open()
    expect(w.find('[data-test="inv-banner-failed"]').text()).toContain('沒有完成')
    expect(w.find('[data-test="inv-failure-code"]').text()).toContain('INVENTORY_NEW_ONE')
  })

  it('中斷：說明先前結果不變', async () => {
    getInvMock.mockResolvedValue(inv({ scan: { ...SCAN, status: 'interrupted' } }))
    const w = await open()
    expect(w.find('[data-test="inv-banner-interrupted"]').text()).toContain('先前的結果不變')
  })

  it('表格徽章：含隱藏字元、非英文、同名多筆、已忽略、已不在主機上、可能不完整', async () => {
    const zw = 'ro' + String.fromCodePoint(0x200b) + 'ot'
    getInvMock.mockResolvedValue(
      inv({
        findings: [
          finding({ id: 1, username: zw, uid_conflict: true, incomplete: true }),
          finding({ id: 2, username: 'r' + String.fromCodePoint(0x043e) + 'ot' }),
          finding({ id: 3, username: 'old', status: 'ignored', ignore_reason: '供應商', ignored_by_name: 'bob', present: false }),
        ],
        total: 3,
      })
    )
    const w = await open()
    const html = w.html()
    expect(html).toContain('&lt;U+200B&gt;')
    expect(w.findAll('[data-test="badge-hidden"]').length).toBe(1)
    expect(w.findAll('[data-test="badge-nonascii"]').length).toBeGreaterThanOrEqual(2)
    expect(w.find('[data-test="badge-conflict"]').exists()).toBe(true)
    expect(w.find('[data-test="badge-ignored"]').exists()).toBe(true)
    expect(w.find('[data-test="badge-gone"]').exists()).toBe(true)
    expect(w.find('[data-test="badge-incomplete"]').exists()).toBe(true)
    expect(w.find('.drawer-stub').html()).not.toContain('v-html')
  })

  it('唯讀者沒有操作欄', async () => {
    const w = await open({}, ['asset:view'])
    expect(w.find('[data-test="inv-manage"]').exists()).toBe(false)
    expect(w.find('[data-test="inv-ignore"]').exists()).toBe(false)
    expect(w.findAll('th').length).toBe(6)
  })

  it('篩選切換送出的查詢參數', async () => {
    const w = await open()
    expect(getInvMock.mock.calls[0][1]).toMatchObject({ privileged: true, managed: false, present: true, status: 'open' })
    await w.find('[data-test="inv-filter-ignored"] input').setValue()
    await flushPromises()
    expect(getInvMock.mock.calls.at(-1)[1]).toMatchObject({ status: 'ignored' })
  })

  it('需要處理為空：說明；部分完成再加不完整提醒', async () => {
    getInvMock.mockResolvedValue(inv({ scan: { ...SCAN, status: 'partial' }, findings: [], total: 0 }))
    const w = await open()
    expect(w.find('[data-test="inv-empty"]').text()).toContain('沒有需要處理的帳號')
    expect(w.find('[data-test="inv-empty-partial"]').exists()).toBe(true)
  })

  it('納管鈕送出 manage 事件並帶原始帳號名', async () => {
    const w = await open()
    await w.find('[data-test="inv-manage"]').trigger('click')
    const ev = w.emitted('manage')
    expect(ev).toHaveLength(1)
    expect(ev[0][0].finding.username).toBe('deploy')
    expect(ev[0][0].asset.id).toBe(7)
  })

  it('納管鈕在 manage_accounts 旗標不允許時停用', async () => {
    getAssetMock.mockResolvedValue({
      ...ASSET,
      actions: { discover_accounts: { allowed: true }, manage_accounts: { allowed: false, reason: 'out_of_scope' } },
    })
    const w = await open()
    expect(w.find('[data-test="inv-manage"]').attributes('disabled')).toBeDefined()
  })
})

describe('盤點抽屜：首次記錄指紋提示', () => {
  it('主機金鑰端點回 404 尚無記錄：確認氣泡出現首次記錄指紋一行', async () => {
    getHostKeyMock.mockRejectedValue(apiErr(404, 'NOTFOUND_HOST_KEY'))
    const w = await open()
    expect(w.find('[data-test="inv-fingerprint-line"]').text()).toContain('這次登入會記下目前的指紋')
    expect(w.find('[data-test="inv-fingerprint-unknown"]').exists()).toBe(false)
  })

  it('已有指紋記錄：兩行都不出現', async () => {
    getHostKeyMock.mockResolvedValue({ fingerprint: 'SHA256:x', algorithm: 'ssh-ed25519' })
    const w = await open()
    expect(w.find('[data-test="inv-start"]').exists()).toBe(true)
    expect(w.find('[data-test="inv-fingerprint-line"]').exists()).toBe(false)
    expect(w.find('[data-test="inv-fingerprint-unknown"]').exists()).toBe(false)
  })

  it.each([
    [500, 'INTERNAL_HOST_KEY_QUERY'],
    [403, undefined],
    [404, 'NOTFOUND_ASSET'],
  ])('讀取失敗（%i %s）：不說會記下，改說無法確認', async (status, code) => {
    getHostKeyMock.mockRejectedValue(apiErr(status, code))
    const w = await open()
    expect(w.find('[data-test="inv-fingerprint-line"]').exists()).toBe(false)
    expect(w.find('[data-test="inv-fingerprint-unknown"]').text()).toContain('無法確認是否已記錄')
  })
})

describe('盤點抽屜：納管需要盤點權限點', () => {
  it.each([
    [['asset:view', 'asset:update']],
    [['asset:view']],
  ])('不持 account:discover（%j）：看不到納管，也沒有操作欄', async (perms) => {
    const w = await open({}, perms)
    expect(w.findAll('[data-test="inv-row"]').length).toBe(1)
    expect(w.find('[data-test="inv-manage"]').exists()).toBe(false)
    expect(w.findAll('th').length).toBe(6)
  })

  it('持 account:discover 但沒有 asset:update：納管出現但停用', async () => {
    const w = await open({}, ['asset:view', 'account:discover'])
    expect(w.find('[data-test="inv-manage"]').attributes('disabled')).toBeDefined()
  })
})

describe('盤點抽屜：表格無障礙', () => {
  it('表頭有 scope、表格有標題、複製鈕有可讀名稱', async () => {
    const w = await open()
    const ths = w.findAll('[data-test="inv-table"] th')
    expect(ths.length).toBe(7)
    ths.forEach((th) => expect(th.attributes('scope')).toBe('col'))
    expect(w.find('[data-test="inv-table"] caption').text()).toContain('web-01')
    expect(w.find('[data-test="inv-copy"]').attributes('aria-label')).toBe('複製帳號名')
  })
})

describe('盤點抽屜：錯誤', () => {
  it.each([
    [403, 'inv-forbidden'],
    [404, 'inv-notfound'],
    [500, 'inv-load-error'],
  ])('讀取 %i 就地呈現', async (status, marker) => {
    getInvMock.mockRejectedValue(apiErr(status))
    const w = await open()
    expect(w.find(`[data-test="${marker}"]`).exists()).toBe(true)
    expect(w.find('[data-test="inv-table"]').exists()).toBe(false)
  })

  it.each([
    ['RULE_INVENTORY_PLATFORM_UNSUPPORTED', 422, '只支援 Linux'],
    ['RULE_INVENTORY_NO_ACCOUNT', 422, '沒有堡壘機專用帳號，也沒有預設帳號'],
    ['RULE_INVENTORY_NO_SECRET', 422, '沒有可用的密碼或私鑰'],
    [undefined, 403, '不在你的盤點權限範圍內'],
  ])('發起失敗 %s 在狀態卡內說明', async (code, status, text) => {
    getInvMock.mockResolvedValue(inv({ scan: null, findings: [], total: 0 }))
    const w = await open()
    startMock.mockRejectedValue(apiErr(status, code))
    await w.find('[data-test="inv-confirm-ok"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="inv-start-error"]').text()).toContain(text)
  })

  it('發起遇進行中衝突：說明並重新讀取', async () => {
    getInvMock.mockResolvedValue(inv({ scan: null, findings: [], total: 0 }))
    const w = await open()
    startMock.mockRejectedValue(apiErr(409, 'CONFLICT_INVENTORY_SCAN_RUNNING'))
    getInvMock.mockResolvedValue(inv({ scan: { ...SCAN, status: 'running' } }))
    const before = getInvMock.mock.calls.length
    await w.find('[data-test="inv-confirm-ok"]').trigger('click')
    await flushPromises()
    expect(getInvMock.mock.calls.length).toBeGreaterThan(before)
    expect(w.find('[data-test="inv-start-error"]').text()).toContain('已有一筆盤點在進行')
  })
})

describe('盤點抽屜：忽略與重新開啟', () => {
  it('忽略：理由空白時按鈕停用，送出後重新讀取', async () => {
    const w = await open()
    await w.find('[data-test="inv-ignore"]').trigger('click')
    await flushPromises()
    const submit = w.find('[data-test="ignore-submit"]')
    expect(submit.attributes('disabled')).toBeDefined()
    await w.find('[data-test="ignore-reason"]').setValue('供應商維護帳號')
    expect(w.find('[data-test="ignore-submit"]').attributes('disabled')).toBeUndefined()
    ignoreMock.mockResolvedValue({ id: 1, status: 'ignored' })
    const before = getInvMock.mock.calls.length
    await w.find('[data-test="ignore-submit"]').trigger('click')
    await flushPromises()
    expect(ignoreMock).toHaveBeenCalledWith(7, 1, '供應商維護帳號')
    expect(getInvMock.mock.calls.length).toBeGreaterThan(before)
  })

  it('忽略：超過 500 字就地顯示原因並停用', async () => {
    const w = await open()
    await w.find('[data-test="inv-ignore"]').trigger('click')
    await flushPromises()
    await w.find('[data-test="ignore-reason"]').setValue('a'.repeat(501))
    expect(w.find('[data-test="ignore-problem"]').text()).toContain('500')
    expect(w.find('[data-test="ignore-submit"]').attributes('disabled')).toBeDefined()
  })

  it('忽略：伺服器驗證錯誤在同一位置顯示', async () => {
    const w = await open()
    await w.find('[data-test="inv-ignore"]').trigger('click')
    await flushPromises()
    await w.find('[data-test="ignore-reason"]').setValue('理由')
    ignoreMock.mockRejectedValue(apiErr(400, 'VALIDATION_INVENTORY_IGNORE_REASON'))
    await w.find('[data-test="ignore-submit"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="ignore-problem"]').exists()).toBe(true)
  })

  it('重新開啟成功後重新讀取；結果已不存在時重新讀取', async () => {
    getInvMock.mockResolvedValue(inv({ findings: [finding({ status: 'ignored' })] }))
    const w = await open()
    reopenMock.mockResolvedValue({ id: 1, status: 'open' })
    let before = getInvMock.mock.calls.length
    await w.findAll('.pc-confirm').at(-1).trigger('click')
    await flushPromises()
    expect(reopenMock).toHaveBeenCalledWith(7, 1)
    expect(getInvMock.mock.calls.length).toBeGreaterThan(before)
    reopenMock.mockRejectedValue(apiErr(404, 'NOTFOUND_INVENTORY_FINDING'))
    before = getInvMock.mock.calls.length
    await w.findAll('.pc-confirm').at(-1).trigger('click')
    await flushPromises()
    expect(getInvMock.mock.calls.length).toBeGreaterThan(before)
  })
})
