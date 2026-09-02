import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import AuditExports from '../AuditExports.vue'

// 下載中心。
//
// 斷言重心在五件「錯了就讓使用者拿不到東西、或以為拿得到」的事：
// 1) 只呈現後端給的本人清單——這頁沒有跨帳號檢視面，也不該演一個；
// 2) 五個狀態各自有可辨識的標籤與說明（pending/running 不能與 done 同形）；
// 3) **只有真的拿得到時才有下載鈕**：done 且未逾期；掛一顆按下必然失敗的鈕，
//    等於把後端的收斂錯誤變成使用者的困惑；
// 4) 失敗可重新發起，且送出的是原本那份篩選快照（重組條件會發出另一個範圍）；
// 5) 空清單要說得出下一步在哪，不是一片空白。

enableAutoUnmount(afterEach)

// happy-dom 的 MutationObserver 與 el-table key-render-helper 不相容，
// 以 no-op stub 取代（不影響渲染結果驗證）
class MutationObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)
vi.stubGlobal('ResizeObserver', MutationObserverStub)

const listMock = vi.fn()
const downloadMock = vi.fn()
const createJobMock = vi.fn()
vi.mock('@/api/auditExport', () => ({
  listAuditExportJobs: (...args) => listMock(...args),
  downloadAuditExportJob: (...args) => downloadMock(...args),
  createAuditExportJob: (...args) => createJobMock(...args),
}))

const HOUR = 3600 * 1000
const future = (ms) => new Date(Date.now() + ms).toISOString()
const past = (ms) => new Date(Date.now() - ms).toISOString()

const job = (over = {}) => ({
  id: 1,
  status: 'done',
  requested_at: '2026-08-24T10:00:00+08:00',
  packaged_at: '2026-08-24T10:02:00+08:00',
  expires_at: future(6 * HOUR),
  artifact_size: 5 * 1024 * 1024,
  artifact_sha256: 'a'.repeat(64),
  filter: { user_id: '1', start_time: '2026-08-12T00:00:00+08:00', end_time: '2026-08-12T12:00:00+08:00' },
  ...over,
})

const mountPage = async (payload) => {
  listMock.mockResolvedValue(payload)
  const wrapper = mount(AuditExports, {
    global: { plugins: [ElementPlus] },
  })
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  vi.clearAllMocks()
  downloadMock.mockResolvedValue(new Blob(['zip'], { type: 'application/zip' }))
  createJobMock.mockResolvedValue({ data: { id: 9, status: 'pending' }, deduplicated: false })
})

describe('只列本人', () => {
  it('渲染的就是後端回的那批，且頁面明說只列本人（沒有跨帳號檢視面）', async () => {
    const wrapper = await mountPage({
      data: [job({ id: 11 }), job({ id: 12, status: 'failed' })],
      total: 2,
      page: 1,
      page_size: 20,
    })
    expect(listMock).toHaveBeenCalledWith({ page: 1, page_size: 20 })
    expect(wrapper.find('[data-test="export-status-11"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="export-status-12"]').exists()).toBe(true)
    // 清單外的 id 不會憑空出現
    expect(wrapper.find('[data-test="export-status-13"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="exports-requester-only"]').text()).toContain('本人')
  })

  it('範圍摘要照篩選快照逐項寫出（使用者要分得出兩份包差在哪）', async () => {
    const wrapper = await mountPage({ data: [job({ id: 21 })], total: 1 })
    const scope = wrapper.find('[data-test="export-scope-21"]').text()
    expect(scope).toContain('使用者 #1')
    expect(scope).toContain('2026')
  })
})

// 類別是範圍的一部分（驗收缺陷訂正）。
// 兩種包能證明的事差在「收了哪幾類」，範圍摘要不講類別，使用者就只能靠
// 檔案大小猜自己下載的是哪一份。
describe('範圍摘要含類別', () => {
  it('明寫類別時逐類列名並給總數', async () => {
    const wrapper = await mountPage({
      data: [job({ id: 31, filter: { user_id: '1', types: 'command,clipboard' } })],
      total: 1,
    })
    const scope = wrapper.find('[data-test="export-scope-31"]').text()
    expect(scope).toContain('指令')
    expect(scope).toContain('剪貼簿')
    expect(scope).toContain('共 2 類')
  })

  it('類別缺席＝全收，仍要顯示（否則與只選兩類長得一樣）', async () => {
    const wrapper = await mountPage({
      data: [job({ id: 32, filter: { user_id: '1' } })],
      total: 1,
    })
    const scope = wrapper.find('[data-test="export-scope-32"]').text()
    expect(scope).toContain('共 6 類')
    expect(scope).toContain('連線')
    expect(scope).toContain('告警')
  })

  it('勾選先後不影響呈現順序（同一組類別不得看起來像兩種範圍）', async () => {
    const wrapper = await mountPage({
      data: [job({ id: 33, filter: { user_id: '1', types: 'clipboard,command' } })],
      total: 1,
    })
    const scope = wrapper.find('[data-test="export-scope-33"]').text()
    expect(scope.indexOf('指令')).toBeLessThan(scope.indexOf('剪貼簿'))
  })

  it('篩選快照整個缺席時只講「不知道」，不憑空宣稱全收', async () => {
    const wrapper = await mountPage({
      data: [job({ id: 34, filter: undefined })],
      total: 1,
    })
    const scope = wrapper.find('[data-test="export-scope-34"]').text()
    expect(scope).toContain('範圍未記錄')
    expect(scope).not.toContain('類別')
  })
})

describe('五個狀態各自可辨識', () => {
  const cases = [
    ['pending', '等待打包'],
    ['running', '打包中'],
    ['done', '可下載'],
    ['failed', '打包失敗'],
    ['expired', '已過期'],
  ]

  it('五態逐一有標籤與說明，且彼此不同形', async () => {
    const wrapper = await mountPage({
      data: cases.map(([status], i) => job({ id: 100 + i, status })),
      total: 5,
    })
    const seen = new Set()
    cases.forEach(([status, label], i) => {
      const text = wrapper.find(`[data-test="export-status-${100 + i}"]`).text()
      expect(text, `狀態 ${status} 未標示`).toContain(label)
      seen.add(text)
    })
    expect(seen.size).toBe(5)
  })

  it('失敗列說得出原因（機器碼查譯，不把 export_job.* 原樣丟給使用者）', async () => {
    const wrapper = await mountPage({
      data: [
        job({ id: 31, status: 'failed', error_summary: 'export_job.pack_failed' }),
        job({ id: 32, status: 'failed', error_summary: 'export_job.requester_revoked' }),
        job({ id: 33, status: 'failed', error_summary: '' }),
      ],
      total: 3,
    })
    expect(wrapper.find('[data-test="export-failure-31"]').text()).toContain('重試上限')
    expect(wrapper.find('[data-test="export-failure-32"]').text()).toContain('權限')
    expect(wrapper.find('[data-test="export-failure-33"]').text()).toContain('未記錄')
    expect(wrapper.text()).not.toContain('export_job.')
  })

  it('後端多一個沒譯過的失敗碼：原樣附上代碼，不謊稱「未記錄」（靜默低報沒人會發現）', async () => {
    const wrapper = await mountPage({
      data: [job({ id: 34, status: 'failed', error_summary: 'export_job.disk_full' })],
      total: 1,
    })
    const text = wrapper.find('[data-test="export-failure-34"]').text()
    expect(text).toContain('disk_full')
    expect(text).not.toContain('未記錄')
  })

  it('後端多一個沒譯過的狀態：原樣顯示，不留一列什麼都不寫的空白', async () => {
    const wrapper = await mountPage({
      data: [job({ id: 35, status: 'cancelled' })],
      total: 1,
    })
    expect(wrapper.find('[data-test="export-status-35"]').text()).toContain('cancelled')
    // 值域外的狀態不得意外長出下載鈕
    expect(wrapper.find('[data-test="export-download-35"]').exists()).toBe(false)
  })

  it('過期倒數：未過期報剩餘時間，過期直說已過期', async () => {
    const wrapper = await mountPage({
      data: [
        job({ id: 41, expires_at: future(3 * HOUR) }),
        job({ id: 42, status: 'expired', expires_at: past(HOUR) }),
      ],
      total: 2,
    })
    expect(wrapper.find('[data-test="export-expiry-41"]').text()).toContain('剩餘')
    expect(wrapper.find('[data-test="export-expiry-42"]').text()).toContain('已過期')
  })
})

describe('下載鈕只在真的拿得到時出現', () => {
  it('done 且未逾期才有下載鈕；其餘四態一律沒有', async () => {
    const wrapper = await mountPage({
      data: [
        job({ id: 51, status: 'done' }),
        job({ id: 52, status: 'pending', artifact_size: 0, expires_at: null }),
        job({ id: 53, status: 'running', artifact_size: 0, expires_at: null }),
        job({ id: 54, status: 'failed', artifact_size: 0, expires_at: null }),
        job({ id: 55, status: 'expired', expires_at: past(HOUR) }),
      ],
      total: 5,
    })
    expect(wrapper.find('[data-test="export-download-51"]').exists()).toBe(true)
    for (const id of [52, 53, 54, 55]) {
      expect(
        wrapper.find(`[data-test="export-download-${id}"]`).exists(),
        `id ${id} 不該有下載鈕`
      ).toBe(false)
    }
  })

  it('狀態還停在 done 但時刻已過期：不給下載（清掃是輪詢式的，以時刻為準）', async () => {
    const wrapper = await mountPage({
      data: [job({ id: 61, status: 'done', expires_at: past(60 * 1000) })],
      total: 1,
    })
    expect(wrapper.find('[data-test="export-download-61"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="export-expiry-61"]').text()).toContain('已過期')
  })

  it('按下下載走 job 下載端點並觸發另存', async () => {
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

    const wrapper = await mountPage({ data: [job({ id: 71 })], total: 1 })
    await wrapper.find('[data-test="export-download-71"]').trigger('click')
    await flushPromises()

    expect(downloadMock).toHaveBeenCalledWith(71)
    expect(clicked[0]).toBe('audit-evidence-job-71.zip')
    document.createElement.mockRestore()
  })
})

describe('失敗可重新發起', () => {
  it('failed 列有重發起鈕，送出的是原本那份篩選快照（不重組條件）', async () => {
    const filter = { asset_id: '7', start_time: '2026-08-01T00:00:00+08:00', end_time: '2026-08-02T00:00:00+08:00' }
    const wrapper = await mountPage({
      data: [job({ id: 81, status: 'failed', filter, artifact_size: 0, expires_at: null })],
      total: 1,
    })
    await wrapper.find('[data-test="export-retry-81"]').trigger('click')
    await flushPromises()
    expect(createJobMock).toHaveBeenCalledWith(filter)
    // 重發起後重新載清單，使用者立刻看得到新的那一列
    expect(listMock).toHaveBeenCalledTimes(2)
  })

  it('done 列不掛重發起鈕（去重只適用進行中，重按只會多產一份沒人要的包）', async () => {
    const wrapper = await mountPage({ data: [job({ id: 82 })], total: 1 })
    expect(wrapper.find('[data-test="export-retry-82"]').exists()).toBe(false)
  })
})

describe('空清單與載入失敗', () => {
  it('沒有任何產物時說得出下一步在哪', async () => {
    const wrapper = await mountPage({ data: [], total: 0 })
    const empty = wrapper.find('[data-test="exports-empty"]')
    expect(empty.exists()).toBe(true)
    expect(empty.text()).toContain('證據包')
    expect(wrapper.find('[data-test="export-status-1"]').exists()).toBe(false)
  })

  it('清單載入失敗要說出來（不得留一片看起來像「沒有產物」的空白）', async () => {
    listMock.mockRejectedValue(new Error('boom'))
    const wrapper = mount(AuditExports, { global: { plugins: [ElementPlus] } })
    await flushPromises()
    expect(wrapper.find('[data-test="exports-load-failed"]').exists()).toBe(true)
  })
})

describe('自動更新', () => {
  it('有 pending/running 才提示自動更新；全終態時不提示（不做沒必要的輪詢）', async () => {
    const active = await mountPage({ data: [job({ id: 91, status: 'running' })], total: 1 })
    expect(active.find('[data-test="exports-polling"]').exists()).toBe(true)

    const settled = await mountPage({ data: [job({ id: 92, status: 'done' })], total: 1 })
    expect(settled.find('[data-test="exports-polling"]').exists()).toBe(false)
  })

  it('卸載後不再發請求（留著的計時器會在離開頁面後繼續打後端）', async () => {
    vi.useFakeTimers()
    listMock.mockResolvedValue({ data: [job({ id: 93, status: 'running' })], total: 1 })
    const wrapper = mount(AuditExports, { global: { plugins: [ElementPlus] } })
    await flushPromises()
    const calls = listMock.mock.calls.length
    wrapper.unmount()
    vi.advanceTimersByTime(60 * 1000)
    expect(listMock.mock.calls.length).toBe(calls)
    vi.useRealTimers()
  })
})

// 「輪替報告」分頁。
//
// 兩件事必須釘住：報告清單以種類參數查詢（缺省種類的「我的匯出」一字未動），
// 以及報告列的下載走的是報告自己的檔名與那一列的 id。
describe('輪替報告分頁', () => {
  const reportJob = (over = {}) => ({
    id: 18,
    kind: 'rotation_report',
    status: 'done',
    requester: 'system',
    requested_at: '2026-09-01T01:00:00+08:00',
    packaged_at: '2026-09-01T01:02:00+08:00',
    expires_at: future(48 * HOUR),
    artifact_size: 75905,
    artifact_sha256: 'b'.repeat(64),
    offsite_status: 'uploaded',
    report: {
      scope_kind: 'all',
      period_start: '2026-08-01T00:00:00+08:00',
      period_end: '2026-09-01T00:00:00+08:00',
      language: 'zh-TW',
      schedule_name: '驗收月報',
      generated_by: '驗收月報',
    },
    ...over,
  })

  const openReportsTab = async (wrapper) => {
    const tabs = wrapper.findAll('.el-tabs__item')
    await tabs[tabs.length - 1].trigger('click')
    await flushPromises()
    return wrapper
  }

  it('報告分頁以 kind=rotation_report 查詢；我的匯出維持缺省種類（一字未動）', async () => {
    listMock.mockImplementation((params) =>
      Promise.resolve(
        params?.kind === 'rotation_report'
          ? { data: [reportJob()], total: 1 }
          : { data: [job({ id: 11 })], total: 1 }
      )
    )
    const wrapper = mount(AuditExports, { global: { plugins: [ElementPlus] } })
    await flushPromises()
    expect(listMock).toHaveBeenCalledWith({ page: 1, page_size: 20 })
    // 我的匯出不列報告：那是另一種產物、另一套清單規則
    expect(wrapper.find('[data-test="export-status-11"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="report-status-18"]').exists()).toBe(false)

    await openReportsTab(wrapper)
    expect(listMock).toHaveBeenCalledWith({ kind: 'rotation_report', page: 1, page_size: 20 })
    expect(wrapper.find('[data-test="report-status-18"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="report-source-18"]').text()).toContain('驗收月報')
    expect(wrapper.find('[data-test="reports-shared-note"]').exists()).toBe(true)
  })

  it('報告列可下載，取的是該列的產物；手動產出標為手動', async () => {
    listMock.mockImplementation((params) =>
      Promise.resolve(
        params?.kind === 'rotation_report'
          ? {
            data: [reportJob({ id: 19, requester: 'admin', report: { scope_kind: 'node', period_start: '2026-08-01T00:00:00+08:00', period_end: '2026-09-01T00:00:00+08:00', language: 'zh-TW', generated_by: 'admin' } })],
            total: 1,
          }
          : { data: [], total: 0 }
      )
    )
    const wrapper = mount(AuditExports, { global: { plugins: [ElementPlus] } })
    await flushPromises()
    await openReportsTab(wrapper)

    expect(wrapper.find('[data-test="report-source-19"]').text()).toContain('手動')
    const btn = wrapper.find('[data-test="report-download-19"]')
    expect(btn.exists()).toBe(true)
    await btn.trigger('click')
    await flushPromises()
    expect(downloadMock).toHaveBeenCalledWith(19)
  })

  it('沒有報告時說得出下一步在哪，而不是一片空白', async () => {
    listMock.mockResolvedValue({ data: [], total: 0 })
    const wrapper = mount(AuditExports, { global: { plugins: [ElementPlus] } })
    await flushPromises()
    await openReportsTab(wrapper)
    expect(wrapper.find('[data-test="reports-empty"]').exists()).toBe(true)
  })
})
