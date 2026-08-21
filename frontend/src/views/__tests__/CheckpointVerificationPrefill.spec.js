// 檢查點驗證頁消費工作台帶來的範圍（?seq_from=&seq_to=，
// workbench-exits-and-export 出口 B／tasks 2.1-2.3）。
//
// **本檔最重要的一條是「不自動觸發」。** 內容層驗證對範圍大小無上限，工作台帶來的
// 是「已清除檢查點的最小／最大序號」，該閉區間中間可能夾著大量未清除區間——那些
// 區間要 COUNT(*)＋重算聚合＋逐列比對。而這個 URL 可分享、可加書籤、可重整：
// 自動觸發等於每開一次連結就跑一次無界重掃。故掛載路徑上**絕不**呼叫內容層端點，
// 只把欄位填好，讓成本以一次刻意的點擊被看見。
//
// 本檔與 CheckpointVerification.spec.js 分檔並存：那支守文案與版面，本支守深連結
// 行為，兩者的 route mock 需求不同（本支要能逐案換 query）。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'

enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

vi.setConfig({ testTimeout: 20_000 })

const verifyChainMock = vi.fn()
const listCheckpointsMock = vi.fn()
const getPublicKeyMock = vi.fn()
const verifyContentMock = vi.fn()
const routeQuery = { value: {} }

vi.mock('@/api/auditCheckpoints', () => ({
  verifyChain: (...a) => verifyChainMock(...a),
  listCheckpoints: (...a) => listCheckpointsMock(...a),
  getCheckpointPublicKey: (...a) => getPublicKeyMock(...a),
  verifyCheckpointContent: (...a) => verifyContentMock(...a),
}))

vi.mock('vue-router', () => ({
  useRoute: () => ({ query: routeQuery.value }),
}))

import CheckpointVerification from '../CheckpointVerification.vue'

const mountPage = () =>
  mount(CheckpointVerification, { global: { plugins: [ElementPlus] } })

const inputValue = (wrapper, testId) =>
  wrapper.find(`[data-test="${testId}"] input`).element.value

beforeEach(() => {
  vi.clearAllMocks()
  routeQuery.value = {}
  verifyChainMock.mockResolvedValue({
    data: {
      chain: {
        total: 12,
        latest_seq: 12,
        oldest_seq: 1,
        passed: 12,
        failed: 0,
        status: 'passed',
        failures: [],
        unsealed_rows: 0,
        anchor_disabled: false,
        seal_interval_seconds: 3600,
        seal_row_threshold: 10000,
      },
    },
  })
  listCheckpointsMock.mockResolvedValue({ data: { items: [], total: 0 } })
  getPublicKeyMock.mockResolvedValue({ data: { algorithm: 'Ed25519' } })
  verifyContentMock.mockResolvedValue({ data: { content: { intervals: [] } } })
})

describe('檢查點驗證頁：範圍預填', () => {
  it('合法成對範圍填入兩個欄位並標示來源', async () => {
    routeQuery.value = { seq_from: '10', seq_to: '42' }

    const wrapper = mountPage()
    await flushPromises()

    expect(inputValue(wrapper, 'seq-from')).toBe('10')
    expect(inputValue(wrapper, 'seq-to')).toBe('42')
    expect(wrapper.find('[data-test="range-prefilled"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="range-prefill-ignored"]').exists()).toBe(false)
  })

  it.each([
    ['只帶起始', { seq_from: '10' }],
    ['只帶結束', { seq_to: '42' }],
    ['非數字', { seq_from: 'abc', seq_to: '42' }],
    ['起始大於結束', { seq_from: '99', seq_to: '42' }],
    ['零', { seq_from: '0', seq_to: '42' }],
    ['負值', { seq_from: '-3', seq_to: '42' }],
    ['小數', { seq_from: '1.5', seq_to: '42' }],
  ])('%s：欄位保持空白並說明未套用原因（不半填）', async (_name, query) => {
    routeQuery.value = query

    const wrapper = mountPage()
    await flushPromises()

    expect(inputValue(wrapper, 'seq-from')).toBe('')
    expect(inputValue(wrapper, 'seq-to')).toBe('')
    expect(wrapper.find('[data-test="range-prefill-ignored"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="range-prefilled"]').exists()).toBe(false)
  })

  it('未帶參數時兩個提示都不出現（原行為不變）', async () => {
    const wrapper = mountPage()
    await flushPromises()

    expect(wrapper.find('[data-test="range-prefilled"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="range-prefill-ignored"]').exists()).toBe(false)
  })

  it('預填文案不裸露內部參數名，且明示耗時', async () => {
    routeQuery.value = { seq_from: '10', seq_to: '42' }

    const wrapper = mountPage()
    await flushPromises()

    const text = wrapper.find('[data-test="range-prefilled"]').text()
    expect(text).not.toMatch(/seq/i)
    expect(text).toContain('耗時')
  })
})

describe('檢查點驗證頁：預填絕不自動觸發內容層驗證', () => {
  it('帶合法範圍掛載後，內容層端點呼叫次數為 0', async () => {
    routeQuery.value = { seq_from: '1', seq_to: '999999' }

    const wrapper = mountPage()
    await flushPromises()

    // 掛載該做的三件事都做了（證明本測試不是因為元件沒起來才綠）
    expect(verifyChainMock).toHaveBeenCalledTimes(1)
    expect(listCheckpointsMock).toHaveBeenCalledTimes(1)
    expect(getPublicKeyMock).toHaveBeenCalledTimes(1)
    // 唯獨內容層一次都不能跑
    expect(verifyContentMock).toHaveBeenCalledTimes(0)
    expect(inputValue(wrapper, 'seq-from')).toBe('1')
  })

  it('使用者按下執行鍵才跑，且帶的是預填的範圍', async () => {
    routeQuery.value = { seq_from: '10', seq_to: '42' }

    const wrapper = mountPage()
    await flushPromises()
    expect(verifyContentMock).toHaveBeenCalledTimes(0)

    await wrapper.find('[data-test="run-content"]').trigger('click')
    await flushPromises()

    expect(verifyContentMock).toHaveBeenCalledTimes(1)
    expect(verifyContentMock).toHaveBeenCalledWith({ seq_from: 10, seq_to: 42 })
  })

  it('重新整理（重新掛載）同一條連結仍是零次內容層呼叫', async () => {
    routeQuery.value = { seq_from: '1', seq_to: '999999' }

    mountPage()
    await flushPromises()
    mountPage()
    await flushPromises()

    expect(verifyContentMock).toHaveBeenCalledTimes(0)
  })
})
