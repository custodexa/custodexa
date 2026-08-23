import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import AuditWorkbench from '../AuditWorkbench.vue'
import TimelineEvents from '@/components/audit/TimelineEvents.vue'

// 稽核調查工作台（auditor-workbench）。
//
// 斷言重心在四件規格明文要求的事：
// 1) 全部狀態進 query string 且貼上 URL 可還原；
// 2) 關閉的類別不送查詢（types 縮減、全關不打 API）；
// 3) 保留三態＋present 空集合**都有標記**——任何空白區間無標記都會被讀成「紀錄被刪」；
// 4) 跨度條四種情形與錄影三態各自可辨識，且 aria-label 帶人／資產／起訖／時長。

enableAutoUnmount(afterEach)

class ObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', ObserverStub)
vi.stubGlobal('ResizeObserver', ObserverStub)

// route 以純物件模擬：頁面對 URL 的寫入走 router.replace，本檔以 replaceSpy
// 攔下並回寫 routeState.query，讓「寫入後再比對」的去重邏輯也在測試中成立
const { routeState } = vi.hoisted(() => ({
  routeState: { path: '/audit/workbench', query: {} },
}))

const replaceSpy = vi.fn((to) => {
  routeState.query = { ...(to?.query || {}) }
  return Promise.resolve()
})
const pushSpy = vi.fn()

vi.mock('vue-router', () => ({
  useRoute: () => routeState,
  useRouter: () => ({
    replace: (...args) => replaceSpy(...args),
    push: (...args) => pushSpy(...args),
  }),
}))

const timelineMock = vi.fn()
const subjectsMock = vi.fn()
vi.mock('@/api/auditTimeline', () => ({
  getAuditTimeline: (...args) => timelineMock(...args),
  getAuditSubjects: (...args) => subjectsMock(...args),
}))

const FROM = '2026-08-12T00:00:00+08:00'
const TO = '2026-08-12T12:00:00+08:00'
const at = (h, m = 0) =>
  `2026-08-12T${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:00+08:00`

const baseQuery = { subject: 'user', id: '1', from: FROM, to: TO }

const payload = (over = {}) => ({
  events: [
    {
      id: 'command:5',
      ts: at(3),
      type: 'command',
      summary_code: 'timeline.command.executed',
      params: { command: 'rm -rf /tmp/x' },
      counterpart: { kind: 'asset', id: 1, name: '測試 SSH' },
      refs: { session_id: 9, asset_id: 1 },
    },
    {
      id: 'alert:2',
      ts: at(4),
      type: 'alert',
      summary_code: 'timeline.alert.triggered',
      params: { rule: '高危指令', command: 'rm -rf /' },
      severity: 'high',
      refs: { session_id: 9, alert_id: 2 },
    },
    {
      id: 'audit_log:77',
      ts: at(5),
      type: 'audit_log',
      // 後端日後新增的 action：必須優雅降級，不得吐 raw i18n key
      summary_code: 'timeline.audit_log.brand_new_action',
      params: { resource: 'asset', status: 'success', path: '/api/v1/assets/1' },
      refs: {},
    },
  ],
  spans: [
    {
      session_id: 9,
      user_id: 1,
      user_name: 'admin',
      asset_id: 1,
      asset_name: '測試 SSH',
      account: 'testuser',
      protocol: 'ssh',
      start: at(2),
      end: at(4),
      status: 'closed',
      recording_state: 'available',
    },
    {
      session_id: 10,
      user_id: 1,
      user_name: 'admin',
      asset_id: 3,
      asset_name: '測試 RDP',
      account: 'testuser',
      protocol: 'rdp',
      start: at(6),
      end: null,
      status: 'active',
      recording_state: 'none',
    },
    {
      session_id: 11,
      user_id: 1,
      user_name: 'admin',
      asset_id: 1,
      asset_name: '測試 SSH',
      account: 'testuser',
      protocol: 'ssh',
      start: '2026-08-11T20:00:00+08:00',
      end: '2026-08-12T20:00:00+08:00',
      status: 'closed',
      recording_state: 'purged',
    },
    {
      session_id: 12,
      user_id: 1,
      user_name: 'admin',
      asset_id: 1,
      asset_name: '測試 SSH',
      account: 'testuser',
      protocol: 'ssh',
      start: at(8),
      end: at(8),
      status: 'closed',
      recording_state: 'none',
    },
  ],
  coverage: [
    { type: 'session', state: 'present' },
    { type: 'command', state: 'present' },
    { type: 'alert', state: 'present' },
    {
      type: 'audit_log',
      state: 'purged',
      policy_days: 90,
      last_purge_at: '2026-08-01T03:00:00+08:00',
      partial: true,
      checkpoint_seq_range: { from: 3, to: 8 },
    },
    { type: 'clipboard', state: 'not_retained' },
    { type: 'file_transfer', state: 'present' },
  ],
  counts: {
    session: 4,
    command: 1,
    alert: 1,
    audit_log: 1,
    clipboard: 0,
    file_transfer: 0,
  },
  truncated: false,
  ...over,
})

// el-date-picker／el-select／el-tooltip 在 happy-dom 下的掛載成本使每個案例
// 逼近 5s 上限（同 MainLayout.spec 的既有教訓）。本檔的斷言都不依賴這三者的
// 內部行為，故以 stub 換取穩定；工作台自己的元件一律真掛載
const mountPage = async () => {
  const wrapper = mount(AuditWorkbench, {
    global: {
      plugins: [ElementPlus],
      stubs: {
        'el-date-picker': true,
        SubjectPicker: true,
        'el-tooltip': { template: '<div><slot /></div>' },
      },
    },
  })
  await flushPromises()
  return wrapper
}

const lastParams = () => timelineMock.mock.calls.at(-1)[0]

beforeEach(() => {
  vi.clearAllMocks()
  routeState.query = { ...baseQuery }
  timelineMock.mockResolvedValue(payload())
  subjectsMock.mockResolvedValue({
    data: [{ id: 1, name: 'admin', display_name: '管理員', active: true, deleted: false }],
    total: 1,
  })
})

describe('狀態與 query string', () => {
  it('URL 帶的 subject／id／時間窗原樣送進查詢（貼連結可還原畫面）', async () => {
    routeState.query = { ...baseQuery, subject: 'asset', id: '7' }
    await mountPage()
    const params = lastParams()
    expect(params.subject).toBe('asset')
    expect(params.subject_id).toBe(7)
    expect(params.from).toBe(FROM)
    expect(params.to).toBe(TO)
  })

  it('未帶時間窗時補上預設窗並寫回 URL（首屏也能被複製還原）', async () => {
    routeState.query = { subject: 'user', id: '1' }
    await mountPage()
    expect(replaceSpy).toHaveBeenCalled()
    const written = replaceSpy.mock.calls.at(-1)[0].query
    expect(written.subject).toBe('user')
    expect(written.from).toMatch(/[+-]\d{2}:\d{2}$/)
    expect(written.to).toMatch(/[+-]\d{2}:\d{2}$/)
  })

  it('未選主體時不送查詢，改出提示', async () => {
    routeState.query = { subject: 'user' }
    const wrapper = await mountPage()
    expect(timelineMock).not.toHaveBeenCalled()
    expect(wrapper.find('[data-test="no-subject"]').exists()).toBe(true)
  })

  it('時間窗顛倒時擋在前端並提示（不打端點吃 400）', async () => {
    routeState.query = { ...baseQuery, from: TO, to: FROM }
    const wrapper = await mountPage()
    expect(timelineMock).not.toHaveBeenCalled()
    expect(wrapper.find('[data-test="range-invalid"]').exists()).toBe(true)
  })
})

describe('類別開關', () => {
  it('預設六類全開，types 帶滿', async () => {
    await mountPage()
    expect(lastParams().types.split(',').sort()).toEqual(
      ['alert', 'audit_log', 'clipboard', 'command', 'file_transfer', 'session'].sort()
    )
  })

  it('關掉一類 → types 縮減且 URL 同步', async () => {
    const wrapper = await mountPage()
    const box = wrapper.find('[data-test="category-clipboard"] input')
    await box.setValue(false)
    await flushPromises()
    expect(lastParams().types).not.toContain('clipboard')
    expect(replaceSpy.mock.calls.at(-1)[0].query.types).not.toContain('clipboard')
  })

  it('全部關閉 → 完全不送查詢並明示', async () => {
    const wrapper = await mountPage()
    const before = timelineMock.mock.calls.length
    await wrapper.find('[data-test="clear-all"]').trigger('click')
    await flushPromises()
    expect(timelineMock.mock.calls.length).toBe(before)
    expect(wrapper.find('[data-test="all-off-hint"]').exists()).toBe(true)
  })

  it('左欄同時給筆數與 coverage 徽章（0 筆的三種成因才分得開）', async () => {
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="count-command"]').text()).toBe('1')
    // 徽章一律帶著「依什麼」或「有沒有被清過」的限定：脫掉限定的
    //「已清除」會被掃徽章的稽核讀成「證據被刪」，「無政策」更是方向相反
    expect(wrapper.find('[data-test="coverage-badge-audit_log"]').text()).toBe('依政策清除')
    expect(wrapper.find('[data-test="coverage-badge-clipboard"]').text()).toBe('未曾清除')
    expect(wrapper.find('[data-test="coverage-badge-session"]').text()).toBe('保留期內')
  })

  it('徽章不得再出現方向相反或無限定的舊說法', async () => {
    const wrapper = await mountPage()
    const panel = wrapper.find('[data-test="category-panel"]').text()
    expect(panel).not.toContain('無政策')
    expect(panel).not.toContain('保留中')
    // 「保留期內」不得被寫成完整性宣稱（本頁不出具完整性證明）
    expect(panel).not.toContain('紀錄完整')
  })

  it('關閉的類別不報 0 筆，改標「未納入查詢」（沒查過不等於沒發生）', async () => {
    routeState.query = { ...baseQuery, types: 'session,command' }
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="count-clipboard"]').text()).toBe('—')
    expect(wrapper.find('[data-test="coverage-badge-clipboard"]').text()).toBe('未納入查詢')
    expect(wrapper.find('[data-test="count-command"]').text()).toBe('1')
  })
})

// 事件軸底部的總筆數。
//
// events.length 是「已抓回的頁數合計」，被截斷時遠小於真實總數；拿它當總數
// 會讓稽核在只看到一部分時誤信自己看完了全部。真總數只有 counts 有
// （不受單次查詢上限影響），故由本頁加總後傳給事件軸
describe('事件總筆數', () => {
  it('傳給事件軸的總數＝開啟中類別的 counts 加總', async () => {
    const wrapper = await mountPage()
    // session 4 ＋ command 1 ＋ alert 1 ＋ audit_log 1 ＋ clipboard 0 ＋ file_transfer 0
    expect(wrapper.findComponent(TimelineEvents).props('total')).toBe(7)
  })

  it('關閉的類別不計入總數（即使回應仍帶著它的筆數）', async () => {
    routeState.query = { ...baseQuery, types: 'command,alert' }
    const wrapper = await mountPage()
    expect(wrapper.findComponent(TimelineEvents).props('total')).toBe(2)
  })

  it('截斷時總數仍是窗內真實筆數，不隨已載入筆數縮水', async () => {
    timelineMock.mockResolvedValue(
      payload({
        truncated: true,
        next_cursor: 'c1',
        counts: {
          session: 4,
          command: 8000,
          alert: 1,
          audit_log: 1,
          clipboard: 0,
          file_transfer: 0,
        },
      })
    )
    const wrapper = await mountPage()
    const events = wrapper.findComponent(TimelineEvents)
    expect(events.props('total')).toBe(8006)
    expect(events.props('events').length).toBeLessThan(8006)
  })
})

describe('保留三態與空白標記', () => {
  it('purged 明寫保留天數與最後清除時刻，partial 另標清除進行中', async () => {
    const wrapper = await mountPage()
    const alert = wrapper.find('[data-test="coverage-purged-audit_log"]')
    expect(alert.exists()).toBe(true)
    expect(alert.text()).toContain('依保留政策清除')
    expect(alert.text()).toContain('保留 90 天')
    expect(alert.text()).toContain('清除作業還在進行中')
    // 「依保留政策清除」而非「已全部刪除」：分批清除與部分完成都可能有殘留
    expect(alert.text()).not.toContain('已全部刪除')
    // 只說「刪了」等於把稽核留在「證據不見了」；必須同時給承擔——
    // 依政策清除本身即政策被落實的證據，且清除動作有留痕
    expect(alert.text()).toContain('不是紀錄遺失')
    expect(alert.text()).toContain('操作日誌')
  })

  it('purged 區間帶提供跳往檢查點驗證頁的連結（帶 seq 區間）', async () => {
    const wrapper = await mountPage()
    await wrapper.find('[data-test="checkpoint-link-audit_log"]').trigger('click')
    expect(pushSpy).toHaveBeenCalledWith({
      path: '/checkpoint-verification',
      query: { seq_from: '3', seq_to: '8' },
    })
  })

  // not_retained 的真義是「這類紀錄不在清除排程內，一筆都沒被刪過」，
  // 與舊文案「無保留政策」方向相反——後者會被稽核逕自寫成內控缺漏。
  // 但「沒被刪過」只能推到「空白不是清除造成的」，推不到「當時什麼都沒發生」：
  // 剪貼簿只在圖形桌面連線採集，終端機與資料庫連線根本不產生剪貼簿紀錄。
  // 這裡的斷言必須與匯出對話框的 export.coverage.not_retained 同語義
  it('not_retained 說明空白的成因，且不得再讀成「保留政策有缺漏」或「確無此類事件」', async () => {
    const wrapper = await mountPage()
    const alert = wrapper.find('[data-test="coverage-not_retained-clipboard"]')
    expect(alert.exists()).toBe(true)
    expect(alert.text()).toContain('不在自動清除的對象內')
    expect(alert.text()).toContain('空白不是清除造成的')
    // 採集邊界必須明說，否則稽核會把空白讀成「確無此類事件」
    expect(alert.text()).toContain('空白也不等於當時沒有事情發生')
    expect(alert.text()).toContain('圖形桌面')
    expect(alert.text()).not.toContain('無保留政策')
    expect(alert.text()).not.toContain('確實沒有發生')
  })

  it('present 且 0 筆標「此區間無紀錄」；present 且有資料不加噪音', async () => {
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="coverage-present-file_transfer"]').text()).toContain(
      '此區間無紀錄'
    )
    expect(wrapper.find('[data-test="coverage-present-command"]').exists()).toBe(false)
  })

  it('四種 coverage 狀態沒有任何一種是無標記的空白', async () => {
    const wrapper = await mountPage()
    const notices = wrapper.find('[data-test="coverage-notices"]').text()
    // 三個需要標記的類別（purged／not_retained／present+0）都要現身
    expect(notices).toContain('操作日誌')
    expect(notices).toContain('剪貼簿')
    expect(notices).toContain('檔案傳輸')
  })
})

describe('會話跨度條', () => {
  it('每條帶 aria-label（使用者／資產／起訖／時長）', async () => {
    const wrapper = await mountPage()
    const label = wrapper.find('[data-test="span-bar-9"]').attributes('aria-label')
    expect(label).toContain('admin')
    expect(label).toContain('測試 SSH')
    expect(label).toContain('2 時')
  })

  it('進行中會話走漸層淡出且標「進行中」，不畫硬邊', async () => {
    const wrapper = await mountPage()
    const bar = wrapper.find('[data-test="span-bar-10"]')
    expect(bar.classes()).toContain('is-ongoing')
    expect(bar.attributes('aria-label')).toContain('進行中')
    expect(wrapper.text()).toContain('進行中')
  })

  it('跨窗會話兩端標裁切', async () => {
    const wrapper = await mountPage()
    const bar = wrapper.find('[data-test="span-bar-11"]')
    expect(bar.classes()).toContain('is-clipped-start')
    expect(bar.classes()).toContain('is-clipped-end')
  })

  it('0 秒會話寬度為 0，靠 CSS min-width 保底可見', async () => {
    const wrapper = await mountPage()
    const bar = wrapper.find('[data-test="span-bar-12"]')
    expect(bar.attributes('style')).toContain('width: 0%')
  })

  it('錄影三態各有可辨識文案', async () => {
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="recording-9"]').text()).toBe('可回放')
    expect(wrapper.find('[data-test="recording-11"]').text()).toBe('錄影已依保留政策清除')
    expect(wrapper.find('[data-test="recording-10"]').text()).toBe('無錄影檔')
  })

  // 後端把「從未錄」與「錄影失敗」壓成同一個 none，而後者是重大缺失：
  // 標籤分不出來時，至少要在提示裡說明怎麼分辨
  it('無錄影檔附「未設定或失敗」的分辨說明，其餘兩態不掛空提示', async () => {
    const wrapper = await mountPage()
    const hint = wrapper.find('[data-test="recording-10"]').attributes('title')
    expect(hint).toContain('未設定')
    expect(hint).toContain('錄影失敗')
    expect(wrapper.find('[data-test="recording-9"]').attributes('title')).toBeUndefined()
  })
})

describe('事件時間軸', () => {
  it('未知 summary_code 走 fallback，不顯示 raw i18n key', async () => {
    const wrapper = await mountPage()
    const text = wrapper.find('[data-test="event-list"]').text()
    expect(text).toContain('尚未支援顯示的事件類型')
    // 機器碼保留（它是唯一可追查的線索），但要說明它是什麼、拿它做什麼
    expect(text).toContain('timeline.audit_log.brand_new_action')
    expect(text).toContain('系統管理員')
    expect(text).not.toContain('auditorWorkbench.summary')
  })

  it('剪貼簿列只說方向，不顯示內容', async () => {
    timelineMock.mockResolvedValue(
      payload({
        events: [
          {
            id: 'clipboard:1',
            ts: at(3),
            type: 'clipboard',
            summary_code: 'timeline.clipboard.send',
            params: {},
            refs: { session_id: 9 },
          },
        ],
      })
    )
    const wrapper = await mountPage()
    const text = wrapper.find('[data-test="event-list"]').text()
    // 方向寫成人的動作（判斷外洩看的就是方向）
    expect(text).toContain('從本機複製內容到遠端主機')
    // 「不顯示內容」要連同「為什麼」與「由什麼承擔」一起講，
    // 否則稽核讀到的是「這個控制查不到東西」
    expect(text).toContain('不顯示在這條時間軸上')
    expect(text).toContain('誰、在哪一場連線、什麼時間、往哪個方向複製')
  })

  it('focus=<type>:<id> 使該列高亮', async () => {
    routeState.query = { ...baseQuery, focus: 'alert:2' }
    const wrapper = await mountPage()
    const focused = wrapper.findAll('[data-test="event-row"]').filter((r) =>
      r.classes().includes('is-focus')
    )
    expect(focused).toHaveLength(1)
    expect(focused[0].text()).toContain('觸發告警規則')
  })

  it('focus 指向不存在的事件時明示，不假裝找到了', async () => {
    routeState.query = { ...baseQuery, focus: 'alert:999' }
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="focus-missing"]').exists()).toBe(true)
  })

  it('截斷時明示，且左欄筆數維持窗內真實筆數', async () => {
    timelineMock.mockResolvedValue(payload({ truncated: true, next_cursor: 'abc' }))
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="events-truncated"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="count-session"]').text()).toBe('4')
    expect(wrapper.find('[data-test="load-more"]').exists()).toBe(true)
  })
})

// 續頁失敗不得與「已經沒有更多」同形。
//
// 修正前失敗處理是 `nextCursor.value = ''`：按鈕消失、頁尾不動、無任何訊息，
// 與「已看完全部」完全一樣——稽核會據此停手，而那一頁根本沒拿到；且游標被
// 丟掉之後，其餘部分在技術上也再取不到
describe('續頁失敗的呈現與重試', () => {
  const truncatedPage = () => payload({ truncated: true, next_cursor: 'abc' })

  it('失敗不清空游標，畫面以錯誤形態明示而非讓按鈕默默消失', async () => {
    timelineMock.mockResolvedValueOnce(truncatedPage())
    const wrapper = await mountPage()
    const events = wrapper.findComponent(TimelineEvents)
    const before = events.props('events').length

    timelineMock.mockRejectedValueOnce(new Error('network'))
    await wrapper.find('[data-test="load-more"]').trigger('click')
    await flushPromises()

    expect(events.props('loadError')).toBe(true)
    // 游標留著＝其餘部分仍取得回來
    expect(events.props('hasMore')).toBe(true)
    expect(wrapper.find('[data-test="events-load-error"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="events-all-shown"]').exists()).toBe(false)
    // 失敗不得假裝拿到了資料
    expect(events.props('events').length).toBe(before)
  })

  it('重試成功後錯誤形態消失，且新內容進入畫面', async () => {
    timelineMock.mockResolvedValueOnce(truncatedPage())
    const wrapper = await mountPage()
    const events = wrapper.findComponent(TimelineEvents)
    const before = events.props('events').length

    timelineMock.mockRejectedValueOnce(new Error('network'))
    await wrapper.find('[data-test="load-more"]').trigger('click')
    await flushPromises()
    expect(events.props('loadError')).toBe(true)

    timelineMock.mockResolvedValueOnce(payload({ truncated: true, next_cursor: 'def' }))
    await wrapper.find('[data-test="load-more-retry"]').trigger('click')
    await flushPromises()

    expect(events.props('loadError')).toBe(false)
    expect(wrapper.find('[data-test="events-load-error"]').exists()).toBe(false)
    expect(events.props('events').length).toBeGreaterThan(before)
    expect(wrapper.find('[data-test="events-status"]').attributes('data-state')).toBe(
      'revealed'
    )
  })
})

describe('純文字降級模式', () => {
  it('view=table 以表格呈現同一份資料', async () => {
    routeState.query = { ...baseQuery, view: 'table' }
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="table-view"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="session-spans"]').exists()).toBe(false)
    const text = wrapper.find('[data-test="table-view"]').text()
    expect(text).toContain('觸發告警規則')
    expect(text).toContain('測試 RDP')
    expect(text).toContain('進行中')
  })
})

describe('誠實邊界', () => {
  // 「本頁不出具完整性證明」這個事實不得弱化，但要正面表述：
  // 說清楚由誰出具，而不是只丟一句「本頁不保證」給稽核
  it('頁面自陳唯讀，且完整性證明指向檢查點驗證頁而非由自己承擔', async () => {
    const wrapper = await mountPage()
    const text = wrapper.text()
    expect(text).toContain('只供查閱')
    expect(text).toContain('不會更動任何紀錄')
    expect(text).toContain('不在這裡判斷紀錄本身有沒有被竄改')
    expect(text).toContain('由「檢查點驗證」頁出具')
    // 工作台自己不得作任何完整性斷言
    expect(text).not.toContain('未被竄改')
    expect(text).not.toContain('紀錄完整')
  })

  // 鏈只聚合 audit_logs（操作日誌與檔案傳輸同住該表），連線／指令／告警／
  // 剪貼簿不在其中。宣稱範圍超出實作，比讀不懂更糟且不可逆
  it('完整性證明的範圍不得被寫得比實作大', async () => {
    const wrapper = await mountPage()
    const text = wrapper.text()
    expect(text).toContain('操作日誌與檔案傳輸的完整性證明')
    expect(text).not.toContain('六類紀錄的完整性')
    expect(text).not.toContain('所有紀錄的完整性')
  })
})
