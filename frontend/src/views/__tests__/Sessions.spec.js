import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Sessions from '../Sessions.vue'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

// happy-dom 的 MutationObserver 與 el-table key-render-helper 不相容，
// 以 no-op stub 取代（與 Assets.spec.js 同法）
class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const pushMock = vi.fn()
vi.mock('vue-router', () => ({ useRouter: () => ({ push: pushMock }) }))

const getSessionListMock = vi.fn()
const getActiveSessionsMock = vi.fn()
const terminateSessionMock = vi.fn()
vi.mock('@/api/sessions', () => ({
  getSessionList: (...a) => getSessionListMock(...a),
  getActiveSessions: (...a) => getActiveSessionsMock(...a),
  terminateSession: (...a) => terminateSessionMock(...a),
}))

const row = (over) => ({
  id: 1,
  session_id: 's-1',
  protocol: 'ssh',
  status: 'closed',
  end_reason: '',
  client_ip: '127.0.0.1',
  start_time: '2026-07-20T08:00:00Z',
  end_time: '2026-07-20T08:10:00Z',
  duration: 600,
  has_recording: false,
  recording_error: '',
  user: { username: 'u1' },
  asset: { name: 'a1', host: 'h', port: 22 },
  ...over,
})

describe('Sessions 無錄影標示', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getActiveSessionsMock.mockResolvedValue([])
    getSessionListMock.mockResolvedValue({
      data: [
        row({ id: 1, recording_error: '啟動錄製失敗: 磁碟空間不足' }),
        row({ id: 2, has_recording: true }),
        row({ id: 3 }),
      ],
      total: 3,
    })
  })

  it('活動連線列表對錄影失敗會話顯警示（人工處置前提：admin 看得到才能斷）', async () => {
    getActiveSessionsMock.mockResolvedValue([
      row({
        id: 9,
        status: 'active',
        recording_error: '錄製 flush 失敗: no space left on device',
      }),
    ])
    const wrapper = mount(Sessions, { global: { plugins: [ElementPlus] } })
    await flushPromises()

    expect(wrapper.text()).toContain('錄影失敗')
    wrapper.unmount()
  }, 15000)

  // recording_error 存的是 cause code
  it('recording_error 為 cause code 時 tooltip 顯詞庫短語，未知值原樣退回', async () => {
    getActiveSessionsMock.mockResolvedValue([
      row({ id: 9, status: 'active', recording_error: 'recording_flush_failed' }),
      row({ id: 10, status: 'active', recording_error: '存量散文：磁碟空間不足' }),
    ])
    const wrapper = mount(Sessions, { global: { plugins: [ElementPlus] } })
    await flushPromises()

    const contents = wrapper
      .findAllComponents({ name: 'ElTooltip' })
      .map((c) => c.props('content'))
      .filter(Boolean)

    // 已知碼：顯示三語詞庫短語，不得漏出裸碼
    expect(contents.some((c) => c.includes('錄製資料落盤失敗'))).toBe(true)
    expect(contents.some((c) => c.includes('recording_flush_failed'))).toBe(false)
    // 存量散文（未碼化）原樣顯示，不吞資訊
    expect(contents.some((c) => c.includes('存量散文：磁碟空間不足'))).toBe(true)
    wrapper.unmount()
  }, 15000)

  it('歷史列表三態：失敗顯「無錄影」tag、有錄影可回放、其餘顯 -', async () => {
    const wrapper = mount(Sessions, { global: { plugins: [ElementPlus] } })
    await flushPromises()

    const historyTab = wrapper
      .findAll('.el-tabs__item')
      .find((el) => el.text().includes('歷史'))
    expect(historyTab).toBeTruthy()
    await historyTab.trigger('click')
    await flushPromises()

    // 失敗列：額外標示（不得只是播放鈕沉默消失）
    expect(wrapper.text()).toContain('無錄影')
    // 僅「有錄影」列提供檢視錄製入口
    const viewBtns = wrapper
      .findAll('button')
      .filter((b) => b.text().includes('檢視錄製'))
    expect(viewBtns.length).toBe(1)
    wrapper.unmount()
  }, 15000)
})

// 連線帳號欄：後端欄位為 `account_username,omitempty`，
// 改名或漏送即靜默變 `-`——兩個分頁各鎖一條，免得回歸時無聲失守
describe('Sessions 連線帳號欄', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getActiveSessionsMock.mockResolvedValue([
      row({ id: 7, status: 'active', account_username: 'root' }),
    ])
    getSessionListMock.mockResolvedValue({
      data: [row({ id: 8, account_username: 'app' }), row({ id: 9 })],
      total: 2,
    })
  })

  it('進行中列表的帳號欄取自該列的 account_username，不是資產或使用者名', async () => {
    getActiveSessionsMock.mockResolvedValue([
      row({ id: 7, status: 'active', account_username: 'root', user: { username: 'alice' } }),
      row({ id: 8, status: 'active', account_username: 'app', user: { username: 'alice' } }),
    ])
    const wrapper = mount(Sessions, { global: { plugins: [ElementPlus] } })
    await flushPromises()

    // 逐列不同值＝確實逐列取用，而非渲染同一個常數
    expect(wrapper.findAll('.account-cell').map((c) => c.text())).toEqual(['root', 'app'])
    wrapper.unmount()
  }, 15000)

  it('歷史列表顯示帳號；無帳號快照（歷史資料）顯 -', async () => {
    const wrapper = mount(Sessions, { global: { plugins: [ElementPlus] } })
    await flushPromises()

    const historyTab = wrapper
      .findAll('.el-tabs__item')
      .find((el) => el.text().includes('歷史'))
    await historyTab.trigger('click')
    await flushPromises()

    // el-tabs 兩個 pane 同時掛載，進行中的 root 也在 DOM 內
    const cells = wrapper.findAll('.account-cell').map((c) => c.text())
    expect(cells).toContain('app')
    // 無 account_username 的歷史列不渲染 .account-cell（落在 `-` 分支）：
    // 兩個 cell＝進行中 root ＋ 歷史 app，第三列（id 9）未產生
    expect(cells).toEqual(['root', 'app'])
    wrapper.unmount()
  }, 15000)
})

// 主控台會話的錄影是轉錄、指令列另有結果欄位：協議 chip 旁必須看得出是哪一種載體
describe('Sessions 主控台小標', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getActiveSessionsMock.mockResolvedValue([])
  })

  it('db_console 為真的列顯示主控台小標，命令列會話不顯示', async () => {
    getSessionListMock.mockResolvedValue({
      data: [
        row({ id: 1, protocol: 'mysql', db_console: true }),
        row({ id: 2, protocol: 'mysql', db_console: false }),
      ],
      total: 2,
    })
    const wrapper = mount(Sessions, { global: { plugins: [ElementPlus] } })
    await flushPromises()
    wrapper.vm.activeTab = 'history'
    wrapper.vm.handleTabChange('history')
    await flushPromises()

    const badges = wrapper.findAll('[data-test="console-badge"]')
    expect(badges).toHaveLength(1)
    expect(badges[0].text()).toBe('主控台')
    wrapper.unmount()
  }, 15000)

  it('活動連線分頁同樣標示（監看要先知道自己要看的是哪一種）', async () => {
    getActiveSessionsMock.mockResolvedValue([
      row({ id: 9, status: 'active', protocol: 'postgres', db_console: true }),
    ])
    getSessionListMock.mockResolvedValue({ data: [], total: 0 })
    const wrapper = mount(Sessions, { global: { plugins: [ElementPlus] } })
    await flushPromises()

    expect(wrapper.findAll('[data-test="console-badge"]').length).toBe(1)
    wrapper.unmount()
  }, 15000)
})
