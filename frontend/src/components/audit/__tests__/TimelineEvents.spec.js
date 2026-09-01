import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mount, enableAutoUnmount, flushPromises } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import { createRouter, createWebHistory } from 'vue-router'
import TimelineEvents from '../TimelineEvents.vue'
import { t } from '@/i18n'

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

// 事件列表的巢狀捲軸已移除（頁面單一捲動路徑，版面資訊層級規格），原本掛在
// 列表身上的 scroll 事件因此永遠不會發生：「捲到底再多渲染一批」改由列表末端
// 的哨兵進入視窗觸發。happy-dom 不排版也不實作 IntersectionObserver，故以
// 測試替身接住 callback，由測試代為宣告「哨兵進入視窗了」
let ioCallbacks = []
class IntersectionObserverStub {
  constructor(cb) {
    this.cb = cb
    ioCallbacks.push(cb)
  }
  observe() {}
  unobserve() {}
  disconnect() {
    ioCallbacks = ioCallbacks.filter((cb) => cb !== this.cb)
  }
}

beforeEach(() => {
  ioCallbacks = []
  globalThis.IntersectionObserver = IntersectionObserverStub
})

const reachListEnd = async (wrapper) => {
  ioCallbacks.slice().forEach((cb) => cb([{ isIntersecting: true }]))
  await flushPromises()
  return wrapper
}

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
    await reachListEnd(wrapper)
    expect(rowCount(wrapper)).toBe(160)
  })

  it('append（游標續頁）不把渲染批次彈回第一批', async () => {
    const first = makeEvents(500)
    const wrapper = mountEvents(first)
    await flushPromises()
    await reachListEnd(wrapper)
    expect(rowCount(wrapper)).toBe(160)

    await wrapper.setProps({ events: [...first, ...makeEvents(500, 500)] })
    await flushPromises()
    expect(rowCount(wrapper)).toBe(160)
  })

  it('換一批查詢結果則重置回第一批', async () => {
    const wrapper = mountEvents(makeEvents(300))
    await flushPromises()
    await reachListEnd(wrapper)
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
    await reachListEnd(wrapper)
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

// 剪貼簿事件的「檢視內容」入口。
//
// 守 href 組裝：`/sessions/:id?t=<秒>#clipboard`——t＝事件時刻 − 會話起點
// 取整秒（與 openSessionByEvent 同法）；span 不在手時退 `at=<RFC3339>`
// （SessionDetail 既有接收端）。無會話參照＝無入口，指出去的路必須存在。
describe('TimelineEvents 剪貼簿檢視內容入口', () => {
  const clipboardEvent = (over) => ({
    id: 'clipboard:1',
    ts: new Date(new Date(FROM).getTime() + 60_000).toISOString(),
    type: 'clipboard',
    summary_code: 'timeline.clipboard.send',
    params: {},
    refs: { session_id: 9 },
    ...over,
  })

  const mountWithRouter = (events, extraProps = {}) => {
    const router = createRouter({
      history: createWebHistory(),
      routes: [
        { path: '/', component: { template: '<div />' } },
        { path: '/sessions/:id', component: { template: '<div />' } },
      ],
    })
    return mount(TimelineEvents, {
      props: { events, from: FROM, to: TO, ...extraProps },
      global: { plugins: [ElementPlus, router] },
    })
  }

  it('span 在手：href 帶 t（事件時刻 − 會話起點取整秒）與 #clipboard', async () => {
    // 會話起點在事件前 18 秒 → t = 60 − 18 = 42
    const spans = [
      {
        session_id: 9,
        start: new Date(new Date(FROM).getTime() + 18_000).toISOString(),
        end: TO,
      },
    ]
    const wrapper = mountWithRouter([clipboardEvent()], { spans })
    await flushPromises()

    const link = wrapper.find('[data-test="clipboard-content-link"]')
    expect(link.exists()).toBe(true)
    expect(link.attributes('href')).toBe('/sessions/9?t=42#clipboard')
  })

  it('span 不在手：退 at=絕對時刻（RFC3339），仍帶 #clipboard', async () => {
    const wrapper = mountWithRouter([clipboardEvent()])
    await flushPromises()

    const href = wrapper.find('[data-test="clipboard-content-link"]').attributes('href')
    expect(href).toContain('/sessions/9')
    expect(decodeURIComponent(href)).toContain(
      `at=${new Date(new Date(FROM).getTime() + 60_000).toISOString()}`
    )
    expect(href).toContain('#clipboard')
    // 相對秒數參數不得同時出現（`at=` 內含 t= 字樣，須以參數邊界比對）
    expect(href).not.toMatch(/[?&]t=/)
  })

  it('無會話參照：不渲染入口（沒有目的地的連結是假話）', async () => {
    const wrapper = mountWithRouter([clipboardEvent({ refs: {} })])
    await flushPromises()

    expect(wrapper.find('[data-test="clipboard-content-link"]').exists()).toBe(false)
    // 註記本身仍在：內容不入時間軸的說明不因無入口而消失
    expect(wrapper.find('.event-note').exists()).toBe(true)
  })

  // 逐列僅留單行短句＋入口，完整理由句收於 tooltip——
  // 多筆剪貼簿事件時不再逐列重複 3 行長註記；語義不減（不攤內容＋指路都在）
  it('多筆剪貼簿事件：逐列單行短句＋入口，完整理由句不逐列攤開', async () => {
    const spans = [{ session_id: 9, start: FROM, end: TO }]
    const wrapper = mountWithRouter(
      [
        clipboardEvent(),
        clipboardEvent({
          id: 'clipboard:2',
          ts: new Date(new Date(FROM).getTime() + 120_000).toISOString(),
        }),
      ],
      { spans }
    )
    await flushPromises()

    const notes = wrapper.findAll('.event-note')
    expect(notes.length).toBe(2)
    notes.forEach((note) => {
      expect(note.text()).toContain('內容刻意不顯示於時間軸')
      // 現在那一頭是「解密調閱」按鈕，不再是展開列即見內容：
      // 指路句照舊寫「展開」會讓人在詳情頁展開後找不到內容而以為壞了
      expect(note.text()).toContain('解密調閱')
      expect(note.text()).not.toContain('逐筆展開')
      expect(note.text()).not.toContain('每次展開')
      expect(note.find('[data-test="clipboard-note-hint"]').exists()).toBe(true)
      expect(note.find('[data-test="clipboard-content-link"]').exists()).toBe(true)
    })
    // 完整長句只活在 tooltip（teleport 至 body），不再逐列鋪進列身
    expect(wrapper.text()).not.toContain('機密再擴散')
  })

  it('非剪貼簿事件不出現此入口', async () => {
    const wrapper = mountWithRouter(makeEvents(3), {
      spans: [{ session_id: 9, start: FROM, end: TO }],
    })
    await flushPromises()

    expect(wrapper.find('[data-test="clipboard-content-link"]').exists()).toBe(false)
  })
})

// —— 來源位址格（來源限定功能）——
//
// 三件錯了就會讓稽核讀出錯誤結論的事：
// 1) 無位址是**顯式的未知＋原因**，不是空白格（空白會被讀成「來源是空的」）；
// 2) 指令／告警／剪貼簿的位址是**所屬連線建線當下**的來源，逐格說明；
// 3) 深連結要帶走當前時間窗與類別，否則點下去等於重來一次調查。
describe('事件列的來源位址', () => {
  const IP = '203.0.113.5'

  const evt = (over = {}) => ({
    id: 'command:1',
    ts: new Date(new Date(FROM).getTime() + 60_000).toISOString(),
    type: 'command',
    summary_code: 'timeline.command.executed',
    params: { command: 'ls' },
    refs: {},
    client_ip: IP,
    ...over,
  })

  const mountWithRouter = (events, extraProps = {}) => {
    const router = createRouter({
      history: createWebHistory(),
      routes: [
        { path: '/', component: { template: '<div />' } },
        { path: '/audit/workbench', component: { template: '<div />' } },
        { path: '/sessions/:id', component: { template: '<div />' } },
      ],
    })
    return mount(TimelineEvents, {
      props: { events, from: FROM, to: TO, ...extraProps },
      global: { plugins: [ElementPlus, router] },
    })
  }

  it('有位址：人樞紐下是深連結，帶當前時間窗與開啟中的類別', async () => {
    const wrapper = mountWithRouter([evt()], {
      subject: 'user',
      types: ['session', 'command'],
    })
    await flushPromises()
    const link = wrapper.find('[data-test="source-link"]')
    expect(link.exists()).toBe(true)
    expect(link.text()).toBe(IP)
    const href = decodeURIComponent(link.attributes('href'))
    expect(href).toContain('/audit/workbench')
    expect(href).toContain('subject=ip')
    expect(href).toContain(`id=${IP}`)
    expect(href).toContain(`from=${FROM}`)
    expect(href).toContain(`to=${TO}`)
    expect(href).toContain('types=session,command')
  })

  it('類別全開時深連結不寫 types（缺席＝全部）', async () => {
    const wrapper = mountWithRouter([evt()], {
      subject: 'asset',
      types: ['session', 'command', 'audit_log', 'file_transfer', 'clipboard', 'alert'],
    })
    await flushPromises()
    const href = wrapper.find('[data-test="source-link"]').attributes('href')
    expect(href).not.toContain('types=')
  })

  it('位址樞紐下自身位址不加連結（連到自己不是導覽）', async () => {
    const wrapper = mountWithRouter([evt()], { subject: 'ip' })
    await flushPromises()
    expect(wrapper.find('[data-test="source-link"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="source-addr"]').text()).toBe(IP)
  })

  it('未知來源三原因各自顯示「未知」標籤，且不加連結', async () => {
    const cases = [
      ['system', '系統發起的動作'],
      ['unresolvable', '寫入當下取不到'],
      ['session_missing', '所屬的連線已不存在'],
    ]
    for (const [reason, expectedText] of cases) {
      const wrapper = mountWithRouter(
        [evt({ client_ip: null, client_ip_reason: reason })],
        { subject: 'user' }
      )
      await flushPromises()
      expect(wrapper.find('[data-test="source-unknown"]').text()).toBe('未知')
      expect(wrapper.find('[data-test="source-link"]').exists()).toBe(false)
      // 原因走 tooltip（teleport 至 body）：以 props 斷言而非撈 DOM 文字
      const cell = wrapper.findComponent({ name: 'SourceAddressCell' })
      expect(cell.props('reason')).toBe(reason)
      // 文案鍵存在且已翻譯（缺鍵時 t() 回鍵名本身，那會把裸機器碼丟給稽核員）
      const text = t(`auditorWorkbench.events.clientIpReason.${reason}`)
      expect(text).not.toContain('auditorWorkbench.')
      expect(text).toContain(expectedText)
      wrapper.unmount()
    }
  })

  it('三句位址語義文案皆存在且彼此不同（壓成同一句就分不出取樣時刻）', () => {
    const texts = ['session', 'request', 'viaSession'].map((k) =>
      t(`auditorWorkbench.events.clientIpScope.${k}`)
    )
    for (const text of texts) expect(text).not.toContain('auditorWorkbench.')
    expect(new Set(texts).size).toBe(3)
    // 指令／告警／剪貼簿那一句必須明說「不是這筆紀錄當下另行取樣」
    expect(texts[2]).toContain('不是這筆紀錄當下另行取樣')
  })

  it('位址的取樣時刻依類別分流（指令屬所屬連線建線當下）', async () => {
    const wrapper = mountWithRouter(
      [
        evt({ id: 'command:1', type: 'command' }),
        evt({ id: 'session:2', type: 'session' }),
        evt({ id: 'audit_log:3', type: 'audit_log' }),
      ],
      { subject: 'ip' }
    )
    await flushPromises()
    const cells = wrapper.findAllComponents({ name: 'SourceAddressCell' })
    expect(cells.map((c) => c.props('eventType'))).toEqual([
      'command',
      'session',
      'audit_log',
    ])
  })

  it('位址樞紐下對造是「誰 · 哪台」兩件事', async () => {
    const wrapper = mountWithRouter(
      [
        evt({
          actor: { kind: 'user', id: 7, name: 'alice' },
          counterpart: { kind: 'asset', id: 1, name: '測試 SSH' },
        }),
      ],
      { subject: 'ip' }
    )
    await flushPromises()
    const party = wrapper.find('[data-test="event-party"]').text()
    expect(party).toContain('alice')
    expect(party).toContain('測試 SSH')
  })

  it('位址樞紐下無 actor 的列標為「未認證來源」，不留白', async () => {
    const wrapper = mountWithRouter([evt({ actor: null })], { subject: 'ip' })
    await flushPromises()
    expect(wrapper.find('[data-test="event-party"]').text()).toContain('未認證來源')
  })

  // 兩件事擠一行時 1440 寬下被欄寬省略號吃掉後半（zh 實測 195px > 180px，
  // en 更長），被吃掉的正是「哪台」。逐行排＝不靠 hover 也讀得到
  it('位址樞紐下「誰」與「哪台」各佔一行，title 仍保留完整單行', async () => {
    const wrapper = mountWithRouter(
      [
        evt({
          actor: { kind: 'user', id: 7, name: 'alice' },
          counterpart: { kind: 'asset', id: 1, name: '測試 SSH' },
        }),
      ],
      { subject: 'ip' }
    )
    await flushPromises()
    const party = wrapper.find('[data-test="event-party"]')
    const lines = party.findAll('.party-line')
    expect(lines).toHaveLength(2)
    expect(lines[0].text()).toContain('alice')
    expect(lines[1].text()).toContain('測試 SSH')
    expect(party.attributes('title')).toContain('alice')
    expect(party.attributes('title')).toContain('測試 SSH')
  })

  it('人／資產樞紐只有對造一件事，仍是單行（不平白多一列空行）', async () => {
    const wrapper = mountWithRouter(
      [evt({ counterpart: { kind: 'asset', id: 1, name: '測試 SSH' } })],
      { subject: 'user' }
    )
    await flushPromises()
    expect(wrapper.find('[data-test="event-party"]').findAll('.party-line')).toHaveLength(1)
  })

  it('人樞紐維持只顯示對造（不冒出「未認證來源」）', async () => {
    const wrapper = mountWithRouter(
      [evt({ counterpart: { kind: 'asset', id: 1, name: '測試 SSH' } })],
      { subject: 'user' }
    )
    await flushPromises()
    const party = wrapper.find('[data-test="event-party"]').text()
    expect(party).toContain('測試 SSH')
    expect(party).not.toContain('未認證來源')
  })
})

describe('空狀態走共用 EmptyState', () => {
  it('人樞紐：狀態句＋下一步指引', async () => {
    const wrapper = mountEvents([], { subject: 'user' })
    await flushPromises()
    const empty = wrapper.find('[data-test="events-empty"]')
    expect(empty.exists()).toBe(true)
    expect(empty.text()).toContain('此區間無事件')
    expect(empty.text()).toContain('放寬時間範圍')
  })

  it('位址樞紐：說出候選口徑與「任一位址可直接輸入」（空≠沒發生過）', async () => {
    const wrapper = mountEvents([], { subject: 'ip' })
    await flushPromises()
    const empty = wrapper.find('[data-test="events-empty"]')
    expect(empty.text()).toContain('此位址在這段期間沒有紀錄')
    expect(empty.text()).toContain('成功登入或建線過的位址')
    expect(empty.text()).toContain('直接輸入')
  })
})

// 不掛規則的告警種類：`rule_name` 存的是機器碼，套一般的「觸發告警規則 {rule}」
// 會在稽核的時間軸上印出裸機器碼。種類由後端隨 params 帶來，按種類換整句
describe('告警事件的摘要依種類分流', () => {
  const alertEvent = (params) => ({
    id: 'alert:1',
    ts: new Date(new Date(FROM).getTime() + 60_000).toISOString(),
    type: 'alert',
    summary_code: 'timeline.alert.triggered',
    params,
    refs: {},
  })

  it('new_source_ip 顯示散文，不顯示 rule_name 的機器碼', async () => {
    const wrapper = mountEvents([
      alertEvent({ rule: 'new_source_ip', kind: 'new_source_ip', reason_code: 'new_source_ip_session' }),
    ])
    await flushPromises()
    const text = wrapper.find('[data-test="event-row"]').text()
    expect(text).toContain('帳號新來源位址')
    expect(text).not.toContain('觸發告警規則 new_source_ip')
  })

  it('規則類告警維持原句（新分支不吃掉既有渲染）', async () => {
    const wrapper = mountEvents([
      alertEvent({ rule: '高危指令', kind: 'rule', command: 'rm -rf /' }),
    ])
    await flushPromises()
    expect(wrapper.find('[data-test="event-row"]').text()).toContain('觸發告警規則 高危指令')
  })
})
