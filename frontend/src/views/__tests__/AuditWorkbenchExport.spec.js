import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import AuditWorkbench from '../AuditWorkbench.vue'

// 工作台的匯出出口。
//
// 斷言重心在四件「錯了就會讓稽核拿著一份誤導文件走人」的事：
// 1) 送出的範圍＝畫面上的範圍（樞紐、對象、起訖、開啟中的類別逐項相同）；
// 2) 誠實邊界在**按下之前**呈現，且「能證明什麼」排在「不能證明什麼」之前；
// 3) purged 與 not_retained 各說各話——壓成同一句，本功能要消滅的誤讀就復活；
// 4) 匯出＝報告：文案明說不含剪貼簿內容、檔案本體與錄影檔，且不指向不存在的取得入口。

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

const { routeState } = vi.hoisted(() => ({
  routeState: { path: '/audit/workbench', query: {} },
}))

vi.mock('vue-router', () => ({
  useRoute: () => routeState,
  useRouter: () => ({
    replace: (to) => {
      routeState.query = { ...(to?.query || {}) }
      return Promise.resolve()
    },
    push: vi.fn(),
  }),
}))

const timelineMock = vi.fn()
vi.mock('@/api/auditTimeline', () => ({
  getAuditTimeline: (...args) => timelineMock(...args),
  getAuditSubjects: vi.fn().mockResolvedValue({ data: [], total: 0 }),
}))

const exportMock = vi.fn()
const publicKeyMock = vi.fn()
// createAuditExportJob 是證據包（非同步）那條路；本檔驗的是預設的事件報告
// 同步路徑，故只需存在於 mock，不應被呼叫（下方一條斷言盯著）
const createJobMock = vi.fn()
vi.mock('@/api/auditExport', () => ({
  exportAuditEvidence: (...args) => exportMock(...args),
  getExportSigningPublicKey: (...args) => publicKeyMock(...args),
  createAuditExportJob: (...args) => createJobMock(...args),
}))

const FROM = '2026-08-12T00:00:00+08:00'
const TO = '2026-08-12T12:00:00+08:00'
const baseQuery = { subject: 'user', id: '1', from: FROM, to: TO }

const payload = (over = {}) => ({
  events: [],
  spans: [
    {
      session_id: 9,
      user_id: 1,
      user_name: 'admin',
      asset_id: 7,
      asset_name: '測試 SSH',
      account: 'testuser',
      protocol: 'ssh',
      start: '2026-08-12T02:00:00+08:00',
      end: '2026-08-12T04:00:00+08:00',
      status: 'closed',
      recording_state: 'available',
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
      purged_through_at: '2026-08-01T00:00:00+08:00',
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

// el-dialog teleport 到 body，happy-dom 下 wrapper 撈不到——inline stub 保留
// 預設插槽與 footer，斷言仍看得到真實文案與真實按鈕
const dialogStub = {
  props: ['modelValue'],
  template:
    '<div v-if="modelValue" data-test="export-dialog"><slot /><slot name="footer" /></div>',
}

const mountPage = async () => {
  const wrapper = mount(AuditWorkbench, {
    global: {
      plugins: [ElementPlus],
      stubs: {
        'el-date-picker': true,
        SubjectPicker: true,
        'el-tooltip': { template: '<div><slot /></div>' },
        'el-dialog': dialogStub,
      },
    },
  })
  await flushPromises()
  return wrapper
}

const openDialog = async (wrapper) => {
  await wrapper.find('[data-test="open-export"]').trigger('click')
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  vi.clearAllMocks()
  routeState.query = { ...baseQuery }
  timelineMock.mockResolvedValue(payload())
  exportMock.mockResolvedValue(new Blob(['zip'], { type: 'application/zip' }))
  publicKeyMock.mockResolvedValue({ data: { algorithm: 'Ed25519', public_key: 'AAA=' } })
})

describe('匯出範圍＝畫面範圍', () => {
  it('送出的參數與時間軸查詢的五項逐項相同（使用者拿到的就是他正在看的那一段）', async () => {
    routeState.query = { ...baseQuery, subject: 'asset', id: '7', types: 'session,command' }
    const wrapper = await mountPage()
    await openDialog(wrapper)
    await wrapper.find('[data-test="export-confirm"]').trigger('click')
    await flushPromises()

    const timelineParams = timelineMock.mock.calls.at(-1)[0]
    const exportParams = exportMock.mock.calls.at(-1)[0]
    expect(exportParams).toEqual({
      subject: 'asset',
      asset_id: 7,
      start_time: FROM,
      end_time: TO,
      types: 'session,command',
    })
    // 同源比對：兩支請求描述的是同一個範圍
    expect(exportParams.subject).toBe(timelineParams.subject)
    expect(exportParams.asset_id).toBe(timelineParams.subject_id)
    expect(exportParams.start_time).toBe(timelineParams.from)
    expect(exportParams.end_time).toBe(timelineParams.to)
    expect(exportParams.types).toBe(timelineParams.types)
  })

  it('關掉一類之後匯出，送出的 types 隨之縮減（不是「全部」）', async () => {
    const wrapper = await mountPage()
    // 類別選擇已由左欄核取方塊改為篩選列 chips（版面資訊層級規格）：
    // 載體換了，「關掉的類別不進匯出範圍」這條語義逐字不變
    await wrapper.find('[data-test="category-clipboard"]').trigger('click')
    await flushPromises()
    await openDialog(wrapper)
    await wrapper.find('[data-test="export-confirm"]').trigger('click')
    await flushPromises()

    const types = exportMock.mock.calls.at(-1)[0].types.split(',')
    expect(types).not.toContain('clipboard')
    expect(types).toContain('session')
    expect(exportMock.mock.calls.at(-1)[0].user_id).toBe(1)
  })

  it('預設包型是事件報告：走同步端點，不會偷偷發起一份背景打包', async () => {
    const wrapper = await mountPage()
    await openDialog(wrapper)
    await wrapper.find('[data-test="export-confirm"]').trigger('click')
    await flushPromises()
    expect(exportMock).toHaveBeenCalledTimes(1)
    expect(createJobMock).not.toHaveBeenCalled()
  })

  it('以人調查時帶 user_id、以資產調查時帶 asset_id（樞紐不會帶錯欄）', async () => {
    const wrapper = await mountPage()
    await openDialog(wrapper)
    await wrapper.find('[data-test="export-confirm"]').trigger('click')
    await flushPromises()
    expect(exportMock.mock.calls.at(-1)[0]).toMatchObject({ subject: 'user', user_id: 1 })
    expect(exportMock.mock.calls.at(-1)[0].asset_id).toBeUndefined()
  })

  it('對話框上半把範圍逐項寫給使用者看（對象、期間、類別、各類筆數）', async () => {
    const wrapper = await mountPage()
    await openDialog(wrapper)
    expect(wrapper.find('[data-test="export-scope-subject"]').text()).toContain('admin')
    expect(wrapper.find('[data-test="export-scope-types"]').text()).toContain('共 6 類')
    const counts = wrapper.find('[data-test="export-scope-counts"]').text()
    expect(counts).toContain('連線 4')
    expect(counts).toContain('剪貼簿 0')
  })

  it('範圍不完整時兩顆入口都不給按（沒有對象＝沒有「目前的調查範圍」）', async () => {
    routeState.query = { subject: 'user' }
    const wrapper = await mountPage()
    expect(
      wrapper.find('[data-test="open-export"]').attributes('disabled')
    ).toBeDefined()
    expect(
      wrapper.find('[data-test="open-export-bundle"]').attributes('disabled')
    ).toBeDefined()
    expect(wrapper.find('[data-test="export-dialog"]').exists()).toBe(false)
  })

  // 位址樞紐沒有匯出（匯出端點的範圍鍵只有 user_id／asset_id）。
  // 範圍是齊的卻不給按，理由必須說得出替代路徑，否則讀起來像壞掉
  it('位址樞紐即使範圍齊全也不給按，且對話框開不起來', async () => {
    routeState.query = { subject: 'ip', id: '203.0.113.5', from: FROM, to: TO }
    const wrapper = await mountPage()
    const report = wrapper.find('[data-test="open-export"]')
    expect(report.attributes('disabled')).toBeDefined()
    expect(report.attributes('title')).toContain('切換到「以人調查」或「以資產調查」')
    await report.trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-test="export-dialog"]').exists()).toBe(false)
    expect(exportMock).not.toHaveBeenCalled()
  })

  // 匯出端點沒有 client_ip 參數：畫面套著位址篩選時，拿到的是**篩選前**的
  // 全部紀錄。不明說，使用者會以為那份就是他正在看的那一小段
  it('畫面套著位址篩選時，範圍段明示該篩選不在匯出範圍內', async () => {
    routeState.query = { ...baseQuery, ip: '203.0.113.5' }
    const wrapper = await mountPage()
    await openDialog(wrapper)
    const caveat = wrapper.find('[data-test="export-scope-ip-filter"]')
    expect(caveat.exists()).toBe(true)
    expect(caveat.text()).toContain('不會套用到這份')
    // 送出的參數確實沒有位址條件（文案說的與實際送的一致）
    await wrapper.find('[data-test="export-confirm"]').trigger('click')
    await flushPromises()
    expect(exportMock.mock.calls.at(-1)[0].client_ip).toBeUndefined()
  })

  // counts 由時間軸查詢帶回、**吃 client_ip**，匯出端點卻不吃：同一段裡若一邊
  // 列篩選後的數字、一邊說收錄篩選前的全部，讀者只能二選一相信。筆數行必須
  // 自報口徑，兩者的關係由但書收束
  it('套著位址篩選時筆數行自報「篩選後」口徑，且但書說明實收不會更少', async () => {
    routeState.query = { ...baseQuery, ip: '203.0.113.5' }
    const wrapper = await mountPage()
    await openDialog(wrapper)
    const counts = wrapper.find('[data-test="export-scope-counts"]').text()
    expect(counts).toContain('套用來源位址篩選後')
    expect(wrapper.find('[data-test="export-scope-ip-filter"]').text()).toContain(
      '不會少於上面的數字'
    )
  })

  it('沒有位址篩選時不出現那句但書（不是常駐免責）', async () => {
    const wrapper = await mountPage()
    await openDialog(wrapper)
    expect(wrapper.find('[data-test="export-scope-ip-filter"]').exists()).toBe(false)
    // 筆數行也回到原句：沒篩選時加註口徑等於憑空製造一個不存在的但書
    expect(wrapper.find('[data-test="export-scope-counts"]').text()).not.toContain(
      '套用來源位址篩選後'
    )
  })
})

// 4b.2：包型是取件方式與內容的分野（陳述／證物、同步／非同步），
// 藏進對話框內的 radio 等於要使用者先按了才知道有另一種 → 工具列兩顆並排。
// 斷言重心：兩顆各自預選對的包型，且證據包那顆發起時**帶得動類別**
//（4b.1 起證據包也套類別；少了 pack 則整條路徑會被後端判成報告而拒絕）
describe('工具列兩顆並排入口', () => {
  it('兩顆都在，各自標明包型（事件報告／證據包）', async () => {
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="open-export"]').text()).toContain('匯出事件報告')
    expect(wrapper.find('[data-test="open-export-bundle"]').text()).toContain('下載證據包')
  })

  it('按「下載證據包」開起來即證據包態（不必再點一次對話框內的 radio）', async () => {
    const wrapper = await mountPage()
    await wrapper.find('[data-test="open-export-bundle"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-test="export-confirm"]').text()).toBe('發起打包')
    expect(wrapper.find('[data-test="export-limits"]').text()).toContain('這一包不能證明什麼')
  })

  it('按「匯出事件報告」開起來即報告態（兩顆共用對話框，包型不得互相沾黏）', async () => {
    const wrapper = await mountPage()
    await wrapper.find('[data-test="open-export-bundle"]').trigger('click')
    await flushPromises()
    await wrapper.find('[data-test="export-cancel"]').trigger('click')
    await flushPromises()
    await wrapper.find('[data-test="open-export"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-test="export-confirm"]').text()).toBe('產生報告')
  })

  it('證據包發起帶 pack 與畫面上的類別：關掉一類之後，送出的 types 隨之縮減', async () => {
    createJobMock.mockResolvedValue({ data: { id: 5, status: 'pending' }, deduplicated: false })
    const wrapper = await mountPage()
    await wrapper.find('[data-test="category-clipboard"]').trigger('click')
    await flushPromises()
    await wrapper.find('[data-test="open-export-bundle"]').trigger('click')
    await flushPromises()
    await wrapper.find('[data-test="export-confirm"]').trigger('click')
    await flushPromises()

    const sent = createJobMock.mock.calls.at(-1)[0]
    expect(sent).toMatchObject({
      pack: 'evidence_bundle',
      subject: 'user',
      user_id: 1,
      start_time: FROM,
      end_time: TO,
    })
    const types = sent.types.split(',')
    expect(types).not.toContain('clipboard')
    expect(types).toContain('session')
    // 走的是非同步發起，不得順手打同步端點（那條會直接吐一個大檔案下來）
    expect(exportMock).not.toHaveBeenCalled()
  })
})

describe('誠實邊界在按下之前呈現', () => {
  it('「能證明什麼」排在「不能證明什麼」之前', async () => {
    const wrapper = await mountPage()
    await openDialog(wrapper)
    const html = wrapper.html()
    expect(html.indexOf('data-test="export-proves"')).toBeGreaterThan(-1)
    expect(html.indexOf('data-test="export-proves"')).toBeLessThan(
      html.indexOf('data-test="export-limits"')
    )
  })

  it('六條邊界在下載前全部到齊', async () => {
    const wrapper = await mountPage()
    await openDialog(wrapper)
    for (const code of [
      'payload_excluded',
      'scope_is_query_range',
      'coverage_states',
      'coverage_states_detail',
      'recording_state',
      'csv_formula_escape',
      'manifest_required',
      'no_offline_tool',
    ]) {
      expect(
        wrapper.find(`[data-test="export-limit-${code}"]`).exists(),
        `缺邊界 ${code}`
      ).toBe(true)
    }
  })

  it('匯出＝報告：明說不含剪貼簿內容、檔案本體與錄影檔，且指得出取得內容的真實途徑', async () => {
    const wrapper = await mountPage()
    await openDialog(wrapper)
    const text = wrapper.find('[data-test="export-limit-payload_excluded"]').text()
    expect(text).toContain('不含剪貼簿內容')
    expect(text).toContain('錄影檔')
    // 三者不在報告內的原因不同。剪貼簿內容仍在系統內，且**已經有兩條真實途徑**
    // 取得（會話詳情逐筆解密調閱、證據包）——這一條必須指得出去哪裡拿。
    // 原文案寫「畫面上沒有入口、請向系統管理員提出」，在那兩條途徑上線後成了
    // 假話，會把稽核推去走一條不存在的流程
    expect(text).toContain('解密調閱')
    expect(text).toContain('證據包')
    expect(text).not.toContain('沒有取得內容的入口')
    expect(text).not.toContain('向系統管理員提出')
    // 檔案本體從來沒被留存過，只有指紋——不是「這次沒放進報告」而是任何時候都取不到
    expect(text).toContain('從未留存')
    expect(text).toContain('指紋')
    // 更舊的文案指引使用者去做一個不存在的動作；退回舊語義必須立刻轉紅
    expect(text).not.toContain('個別下載')
  })

  it('明示匯出的是整個查詢範圍，不是畫面已載入的那幾筆', async () => {
    const wrapper = await mountPage()
    await openDialog(wrapper)
    expect(wrapper.find('[data-test="export-limit-scope_is_query_range"]').text()).toContain(
      '整個查詢範圍'
    )
  })

  it('畫面已截斷時另提示兩種截斷不同源；未截斷時不掛這條噪音', async () => {
    timelineMock.mockResolvedValue(payload({ truncated: true, next_cursor: 'c1' }))
    const wrapper = await mountPage()
    await openDialog(wrapper)
    expect(wrapper.find('[data-test="export-limit-truncated_differs"]').exists()).toBe(true)

    timelineMock.mockResolvedValue(payload())
    const clean = await mountPage()
    await openDialog(clean)
    expect(clean.find('[data-test="export-limit-truncated_differs"]').exists()).toBe(false)
  })

  it('以資產調查時才加上操作紀錄的資產關聯起始邊界', async () => {
    const wrapper = await mountPage()
    await openDialog(wrapper)
    expect(wrapper.find('[data-test="export-limit-asset_scope"]').exists()).toBe(false)

    routeState.query = { ...baseQuery, subject: 'asset', id: '7' }
    const assetPage = await mountPage()
    await openDialog(assetPage)
    expect(assetPage.find('[data-test="export-limit-asset_scope"]').text()).toContain(
      '帶有資產關聯'
    )
  })

  it('邊界文案不裸露內部術語', async () => {
    const wrapper = await mountPage()
    await openDialog(wrapper)
    const text = wrapper.find('[data-test="export-dialog"]').text()
    for (const jargon of ['seq', 'HMAC', 'payload', '水位', '聚合雜湊', '封章', 'JSON']) {
      expect(text, `對外文案出現 ${jargon}`).not.toContain(jargon)
    }
  })
})

describe('purged 與 not_retained 不得被壓平', () => {
  it('purged 說空白是清除的結果，並附保留天數、清除進度與檢查點序號區間', async () => {
    const wrapper = await mountPage()
    await openDialog(wrapper)
    const line = wrapper.find('[data-test="export-coverage-purged-audit_log"]')
    expect(line.exists()).toBe(true)
    expect(line.text()).toContain('依保留政策清除')
    expect(line.text()).toContain('保留 90 天')
    expect(line.text()).toContain('空白是清除的結果')
    expect(line.text()).toContain('檢查點序號 3 至 8')
    // partial：上一次清除沒做完，區間內可能仍有殘留
    expect(line.text()).toContain('未全部完成')
  })

  it('not_retained 說的是「不在自動清除範圍內、空白不是清除造成的」，且點明採集本身有邊界', async () => {
    const wrapper = await mountPage()
    await openDialog(wrapper)
    const notRetained = wrapper.find('[data-test="export-coverage-not_retained-clipboard"]')
    const purged = wrapper.find('[data-test="export-coverage-purged-audit_log"]')
    expect(notRetained.text()).toContain('不在自動清除範圍內')
    // 這條只能否定「清除」這個成因，不能反過來宣告當時什麼都沒發生
    expect(notRetained.text()).toContain('空白不是清除造成的')
    expect(notRetained.text()).toContain('空白也不等於當時沒有事情發生')
    // 採集邊界要講明：剪貼簿只在圖形桌面連線採、且只收文字，終端機／資料庫連線本就不產生
    expect(notRetained.text()).toContain('圖形桌面')
    // 舊文案把空白讀成「確無此類事件」，是本次誠實文案掃描判 FAIL 的那句；退回即轉紅
    expect(notRetained.text()).not.toContain('確無')
    // 方向相反的兩句話不得同形
    expect(notRetained.text()).not.toBe(purged.text())
    expect(notRetained.text()).not.toContain('空白是清除的結果')
  })

  it('present 也有明確標記（六類都不留無標記的空白）', async () => {
    const wrapper = await mountPage()
    await openDialog(wrapper)
    expect(wrapper.findAll('[data-test^="export-coverage-"]')).toHaveLength(6)
    // 用語與工作台徽章 `coverage.badge.present`（「保留期內」）同一說法：
    // 舊值「未被清除」與 not_retained 徽章「未曾清除」只差一字、指的卻是不同狀態
    expect(wrapper.find('[data-test="export-coverage-present-session"]').text()).toContain(
      '保留期內'
    )
  })
})

describe('簽章狀態於下載前告知', () => {
  it('取得到驗證金鑰 → 列出「可獨立驗證」，不出降級提示', async () => {
    const wrapper = await mountPage()
    await openDialog(wrapper)
    expect(wrapper.find('[data-test="export-proves-signature"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="export-unsigned"]').exists()).toBe(false)
  })

  it('端點不存在（404）→ 判定未啟用，出降級提示且不再宣稱可獨立驗證', async () => {
    publicKeyMock.mockRejectedValue({ response: { status: 404 } })
    const wrapper = await mountPage()
    await openDialog(wrapper)
    expect(wrapper.find('[data-test="export-unsigned"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="export-proves-signature"]').exists()).toBe(false)
  })

  it('問不到（斷線）→ 說「無法確認」，不得推論成未啟用', async () => {
    publicKeyMock.mockRejectedValue(new Error('network'))
    const wrapper = await mountPage()
    await openDialog(wrapper)
    expect(wrapper.find('[data-test="export-signing-unknown"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="export-unsigned"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="export-proves-signature"]').exists()).toBe(false)
  })
})

describe('下載與失敗', () => {
  it('成功時觸發另存並關閉對話框', async () => {
    const createURL = vi.fn(() => 'blob:x')
    const revokeURL = vi.fn()
    window.URL.createObjectURL = createURL
    window.URL.revokeObjectURL = revokeURL
    const clicked = []
    const origCreate = document.createElement.bind(document)
    vi.spyOn(document, 'createElement').mockImplementation((tag) => {
      const el = origCreate(tag)
      if (tag === 'a') el.click = () => clicked.push(el.download)
      return el
    })

    const wrapper = await mountPage()
    await openDialog(wrapper)
    await wrapper.find('[data-test="export-confirm"]').trigger('click')
    await flushPromises()

    expect(createURL).toHaveBeenCalled()
    expect(revokeURL).toHaveBeenCalled()
    expect(clicked[0]).toMatch(/^audit-event-report-\d{8}-\d{6}\.zip$/)
    expect(wrapper.find('[data-test="export-dialog"]').exists()).toBe(false)
    document.createElement.mockRestore()
  })

  it('失敗時對話框不關、明說沒拿到任何檔案（下載沒發生與已下載不得同形）', async () => {
    exportMock.mockRejectedValue(new Error('boom'))
    const wrapper = await mountPage()
    await openDialog(wrapper)
    await wrapper.find('[data-test="export-confirm"]').trigger('click')
    await flushPromises()

    expect(wrapper.find('[data-test="export-dialog"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="export-failed"]').text()).toContain('未取得任何檔案')
  })
})
