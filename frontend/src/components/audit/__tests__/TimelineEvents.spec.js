import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount, flushPromises } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import TimelineEvents from '../TimelineEvents.vue'

// 分批渲染（虛擬滾動的等效路徑）的兩條規則：
// 1) 換一批查詢結果 → 重置回第一批；
// 2) 游標續頁（append）→ **不重置**，否則按一次「載入更多」就把使用者
//    剛捲到的位置沒收。

enableAutoUnmount(afterEach)

const FROM = '2026-08-12T00:00:00+08:00'
const TO = '2026-08-12T12:00:00+08:00'

const makeEvents = (n, offset = 0) =>
  Array.from({ length: n }, (_, i) => ({
    id: `command:${offset + i}`,
    ts: new Date(new Date(FROM).getTime() + (offset + i) * 1000).toISOString(),
    type: 'command',
    summary_code: 'timeline.command.executed',
    params: { command: `cmd-${offset + i}` },
    refs: {},
  }))

const mountEvents = (events, extraProps = {}) =>
  mount(TimelineEvents, {
    props: { events, from: FROM, to: TO, ...extraProps },
    global: { plugins: [ElementPlus] },
  })

const rowCount = (w) => w.findAll('[data-test="event-row"]').length

describe('TimelineEvents 分批渲染', () => {
  it('首批只渲染前 80 筆，其餘留給捲動', async () => {
    const wrapper = mountEvents(makeEvents(300))
    await flushPromises()
    expect(rowCount(wrapper)).toBe(80)
    expect(wrapper.find('.footer-hint').text()).toContain('300')
  })

  it('捲到底再多渲染一批', async () => {
    const wrapper = mountEvents(makeEvents(300))
    await flushPromises()
    const list = wrapper.find('[data-test="event-list"]')
    Object.defineProperties(list.element, {
      scrollTop: { value: 1000, configurable: true },
      clientHeight: { value: 400, configurable: true },
      scrollHeight: { value: 1400, configurable: true },
    })
    await list.trigger('scroll')
    expect(rowCount(wrapper)).toBe(160)
  })

  it('append（游標續頁）不把渲染批次彈回第一批', async () => {
    const first = makeEvents(500)
    const wrapper = mountEvents(first)
    await flushPromises()
    const list = wrapper.find('[data-test="event-list"]')
    Object.defineProperties(list.element, {
      scrollTop: { value: 1000, configurable: true },
      clientHeight: { value: 400, configurable: true },
      scrollHeight: { value: 1400, configurable: true },
    })
    await list.trigger('scroll')
    expect(rowCount(wrapper)).toBe(160)

    await wrapper.setProps({ events: [...first, ...makeEvents(500, 500)] })
    await flushPromises()
    expect(rowCount(wrapper)).toBe(160)
  })

  it('換一批查詢結果則重置回第一批', async () => {
    const wrapper = mountEvents(makeEvents(300))
    await flushPromises()
    const list = wrapper.find('[data-test="event-list"]')
    Object.defineProperties(list.element, {
      scrollTop: { value: 1000, configurable: true },
      clientHeight: { value: 400, configurable: true },
      scrollHeight: { value: 1400, configurable: true },
    })
    await list.trigger('scroll')
    expect(rowCount(wrapper)).toBe(160)

    await wrapper.setProps({ events: makeEvents(300, 9000) })
    await flushPromises()
    expect(rowCount(wrapper)).toBe(80)
  })
})

// 這段期間的總筆數與「還有幾筆沒看到」。
//
// 判準不是文案通順，而是**被截斷時讀者會不會停手**：畫面上必須有一個
// 不受單次查詢上限影響的總數，以及它與已顯示筆數的差。
describe('TimelineEvents 總筆數', () => {
  it('total 為窗內真實總數：rest ＝ 總數 − 已顯示的批次量', async () => {
    const wrapper = mountEvents(makeEvents(300), { total: 5000 })
    await flushPromises()
    expect(rowCount(wrapper)).toBe(80)
    expect(wrapper.vm.totalCount).toBe(5000)
    expect(wrapper.vm.restCount).toBe(4920)
  })

  it('多渲染一批後未顯示筆數隨之下降（總數不動）', async () => {
    const wrapper = mountEvents(makeEvents(300), { total: 5000 })
    await flushPromises()
    const list = wrapper.find('[data-test="event-list"]')
    Object.defineProperties(list.element, {
      scrollTop: { value: 1000, configurable: true },
      clientHeight: { value: 400, configurable: true },
      scrollHeight: { value: 1400, configurable: true },
    })
    await list.trigger('scroll')
    expect(wrapper.vm.totalCount).toBe(5000)
    expect(wrapper.vm.restCount).toBe(4840)
  })

  it('全部顯示完畢時未顯示筆數為 0', async () => {
    const wrapper = mountEvents(makeEvents(20), { total: 20 })
    await flushPromises()
    expect(wrapper.vm.restCount).toBe(0)
  })

  // 少報總數＝畫面上列了 300 列卻說「共 80 筆」，那是自己拆自己的台。
  // total 缺席時寧可退回已抓回的筆數，也不可低於已列出的列數
  it('未傳 total 時退回已抓回筆數，不低於已列出的列數', async () => {
    const wrapper = mountEvents(makeEvents(300))
    await flushPromises()
    expect(wrapper.vm.totalCount).toBe(300)
    expect(wrapper.vm.restCount).toBe(220)
  })

  it('total 小於已抓回筆數時取大者（不得少報）', async () => {
    const wrapper = mountEvents(makeEvents(300), { total: 5 })
    await flushPromises()
    expect(wrapper.vm.totalCount).toBe(300)
  })

  // 與截斷提示疊加時才是真實情境：畫面上必須同時看得到「共幾筆」與
  //「還有幾筆沒看到」，否則讀者會在只看到 80 筆時停手
  it('截斷情境下畫面同時給出總數與未顯示筆數', async () => {
    const wrapper = mountEvents(makeEvents(300), { total: 5000, truncated: true })
    await flushPromises()
    expect(wrapper.find('[data-test="events-truncated"]').exists()).toBe(true)
    const footer = wrapper.find('.footer-hint').text()
    expect(footer).toContain('80')
    expect(footer).toContain('5000')
    expect(wrapper.find('[data-test="events-rest"]').text()).toContain('4920')
    // 「已載入」這種實作內部量不得再作為總數出現在文案裡
    expect(footer).not.toContain('已載入')
  })

  it('全部顯示完畢時不再出現「尚有未顯示」', async () => {
    const wrapper = mountEvents(makeEvents(20), { total: 20 })
    await flushPromises()
    expect(wrapper.find('[data-test="events-rest"]').exists()).toBe(false)
  })
})

// 「載入更多」按下之後畫面要**立刻**看得出來發生了什麼。
//
// 修正前：按鈕只向後端續抓，而渲染量只由捲動控制 → 按一次，列數仍 80、
// 頁尾仍寫「已顯示 80 筆」、視野不動，非工程背景的稽核會判定按鈕壞掉。
describe('TimelineEvents 載入更多的可見回饋', () => {
  const clickLoadMore = async (wrapper) => {
    await wrapper.find('[data-test="load-more"]').trigger('click')
    await flushPromises()
  }

  it('本地尚有未渲染時，按下即多渲染一批且不打後端', async () => {
    const wrapper = mountEvents(makeEvents(200), { total: 6165, hasMore: true })
    await flushPromises()
    expect(rowCount(wrapper)).toBe(80)

    await clickLoadMore(wrapper)
    expect(rowCount(wrapper)).toBe(160)
    expect(wrapper.emitted('load-more')).toBeUndefined()
  })

  it('頁尾「已顯示 N 筆」隨按下而變（修正前這個數字不動）', async () => {
    const wrapper = mountEvents(makeEvents(200), { total: 6165, hasMore: true })
    await flushPromises()
    expect(wrapper.find('.footer-hint').text()).toContain('80')
    expect(wrapper.find('[data-test="events-rest"]').text()).toContain('6085')

    await clickLoadMore(wrapper)
    expect(wrapper.find('.footer-hint').text()).toContain('160')
    expect(wrapper.find('[data-test="events-rest"]').text()).toContain('6005')
    expect(wrapper.vm.restCount).toBe(6005)
  })

  it('按下後標出新批次起點列，供視野定位', async () => {
    const wrapper = mountEvents(makeEvents(200), { total: 6165, hasMore: true })
    await flushPromises()
    expect(wrapper.find('[data-batch-start="true"]').exists()).toBe(false)

    await clickLoadMore(wrapper)
    const marked = wrapper.findAll('[data-batch-start="true"]')
    expect(marked).toHaveLength(1)
    // 第 81 筆＝新揭露批次的第一列
    expect(marked[0].text()).toContain('cmd-80')
  })

  it('本地用完才續抓，且該頁抵達後自動揭露（不必再自己捲）', async () => {
    const first = makeEvents(80)
    const wrapper = mountEvents(first, { total: 6165, hasMore: true })
    await flushPromises()
    expect(rowCount(wrapper)).toBe(80)

    await clickLoadMore(wrapper)
    expect(wrapper.emitted('load-more')).toHaveLength(1)
    // 只發事件、資料未到之前，畫面不該假裝多了東西
    expect(rowCount(wrapper)).toBe(80)

    await wrapper.setProps({ events: [...first, ...makeEvents(200, 80)] })
    await flushPromises()
    expect(rowCount(wrapper)).toBe(160)
    expect(wrapper.find('.footer-hint').text()).toContain('160')
  })

  it('續抓中顯示載入狀態，不靜默等待', async () => {
    const wrapper = mountEvents(makeEvents(80), { total: 6165, hasMore: true, loadingMore: true })
    await flushPromises()
    const status = wrapper.find('[data-test="events-status"]')
    expect(status.exists()).toBe(true)
    // 以狀態值斷言而非文案：文案待放行後才寫入 locale，斷言不綁其字面
    expect(status.attributes('data-state')).toBe('loading')
  })

  it('揭露後狀態列說出剛才新增了幾筆', async () => {
    const wrapper = mountEvents(makeEvents(200), { total: 6165, hasMore: true })
    await flushPromises()
    expect(wrapper.find('[data-test="events-status"]').exists()).toBe(false)

    await clickLoadMore(wrapper)
    expect(wrapper.find('[data-test="events-status"]').attributes('data-state')).toBe('revealed')
    expect(wrapper.vm.revealedCount).toBe(80)
  })

  // 「已無更多」與「載入失敗」必須不同形態：兩者都靠「按鈕消失、畫面無訊息」
  // 表達時，失敗會被讀成「我已經看完全部」
  it('揭露完最後一批：明示已無更多，按鈕收起，不出現錯誤形態', async () => {
    const wrapper = mountEvents(makeEvents(120), { total: 120 })
    await flushPromises()
    await clickLoadMore(wrapper)

    expect(rowCount(wrapper)).toBe(120)
    expect(wrapper.find('[data-test="events-all-shown"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="events-load-error"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="load-more"]').exists()).toBe(false)
  })

  it('載入失敗：紅色告警＋重試鍵，與「已無更多」形態不同', async () => {
    const wrapper = mountEvents(makeEvents(80), { total: 6165, hasMore: true, loadError: true })
    await flushPromises()

    const err = wrapper.find('[data-test="events-load-error"]')
    expect(err.exists()).toBe(true)
    // 形態即證據：錯誤態走 el-alert 的 error 樣式，與中性狀態列不同形
    expect(err.html()).toContain('el-alert--error')
    expect(wrapper.find('[data-test="events-all-shown"]').exists()).toBe(false)
    // 失敗態下主按鈕收起，動作入口只有重試鍵一個
    expect(wrapper.find('[data-test="load-more"]').exists()).toBe(false)

    await wrapper.find('[data-test="load-more-retry"]').trigger('click')
    expect(wrapper.emitted('load-more')).toHaveLength(1)
  })

  it('本地已無未渲染且後端也無下一頁時，按鈕不出現', async () => {
    const wrapper = mountEvents(makeEvents(20), { total: 20 })
    await flushPromises()
    expect(wrapper.find('[data-test="load-more"]').exists()).toBe(false)
  })

  it('換一批查詢結果會清掉上一輪的回饋狀態', async () => {
    const wrapper = mountEvents(makeEvents(200), { total: 6165, hasMore: true })
    await flushPromises()
    await clickLoadMore(wrapper)
    expect(wrapper.find('[data-test="events-status"]').exists()).toBe(true)

    await wrapper.setProps({ events: makeEvents(200, 9000) })
    await flushPromises()
    expect(wrapper.find('[data-test="events-status"]').exists()).toBe(false)
    expect(wrapper.find('[data-batch-start="true"]').exists()).toBe(false)
    expect(rowCount(wrapper)).toBe(80)
  })
})
