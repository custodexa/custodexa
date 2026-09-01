// 下載中心的離機保存狀態行（第三列）。
//
// 這一行只回答一件事：**這個包除了本機以外還有沒有副本、那份副本取不取得回來**。
// 因此只呈現對這個問題有答案的狀態；`local_purged`／`skipped_*`／`''` 一律不加行
// ——產物本來就有壽命，本機副本去留由保留清理承擔，多一行只會把真正要看的兩件事
// （已離機保存、離機取回出問題）擠淡。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import AuditExports from '../AuditExports.vue'
import { OFFSITE_EXPORT_ROW_STATUSES, OFFSITE_STATUS_VALUES } from '@/constants/offsite'

enableAutoUnmount(afterEach)

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
vi.mock('@/api/auditExport', () => ({
  listAuditExportJobs: (...args) => listMock(...args),
  downloadAuditExportJob: vi.fn(),
  createAuditExportJob: vi.fn(),
}))

const HOUR = 3600 * 1000
const future = (ms) => new Date(Date.now() + ms).toISOString()

const job = (over = {}) => ({
  id: 1,
  status: 'done',
  requested_at: '2026-08-24T10:00:00+08:00',
  packaged_at: '2026-08-24T10:02:00+08:00',
  expires_at: future(6 * HOUR),
  artifact_size: 5 * 1024 * 1024,
  artifact_sha256: 'a'.repeat(64),
  filter: {},
  offsite_status: '',
  ...over,
})

const mountWith = async (offsiteStatus, over = {}) => {
  listMock.mockResolvedValue({
    data: [job({ id: 21, offsite_status: offsiteStatus, ...over })],
    total: 1,
    page: 1,
    page_size: 20,
  })
  const wrapper = mount(AuditExports, { global: { plugins: [ElementPlus] } })
  await flushPromises()
  return wrapper
}

const line = (wrapper) => wrapper.find('[data-test="export-offsite-21"]')

beforeEach(() => {
  vi.clearAllMocks()
})

describe('加行的狀態', () => {
  const CASES = [
    ['uploaded', '已離機保存'],
    ['pending', '離機上傳待處理'],
    ['uploading', '離機上傳待處理'],
    ['failed', '離機上傳失敗'],
    ['integrity_mismatch', '離機副本完整性不符'],
    ['foreign', '舊儲存設定'],
  ]

  it('對照表與常數的子集逐一相等，缺一即紅', () => {
    expect(CASES.map(([s]) => s).sort()).toEqual([...OFFSITE_EXPORT_ROW_STATUSES].sort())
  })

  it.each(CASES)('狀態 %s 加一行「%s」', async (status, text) => {
    const wrapper = await mountWith(status)
    expect(line(wrapper).exists()).toBe(true)
    expect(line(wrapper).text()).toBe(text)
  })
})

describe('不加行的狀態', () => {
  // 十態扣掉上面的子集，剩下的一律不加行
  const SILENT = OFFSITE_STATUS_VALUES.filter(
    (s) => !OFFSITE_EXPORT_ROW_STATUSES.includes(s)
  )

  it('剩下的四態（含空字串）確實是不加行的那一組', () => {
    expect([...SILENT].sort()).toEqual(
      ['', 'local_purged', 'skipped_expired', 'skipped_missing'].sort()
    )
  })

  it.each(SILENT)('狀態 "%s" 不加行', async (status) => {
    const wrapper = await mountWith(status)
    expect(line(wrapper).exists()).toBe(false)
  })

  it('後端沒回這個欄位（舊版或部署未啟用）時同樣不加行', async () => {
    listMock.mockResolvedValue({
      data: [{ ...job({ id: 21 }), offsite_status: undefined }],
      total: 1,
      page: 1,
      page_size: 20,
    })
    const wrapper = mount(AuditExports, { global: { plugins: [ElementPlus] } })
    await flushPromises()
    expect(line(wrapper).exists()).toBe(false)
  })

  it('值域外的狀態不加行也不顯示裸機器碼', async () => {
    const wrapper = await mountWith('brand_new_state')
    expect(line(wrapper).exists()).toBe(false)
    expect(wrapper.text()).not.toContain('brand_new_state')
  })
})

// 帳冊雜湊（狀態行第三列「已離機保存 · <sha256 前 12>」）：那是遠端那一份
// 的身分，與左欄的產物雜湊不同來源，取不到時這一行只留狀態。
describe('離機雜湊', () => {
  const LEDGER_SHA = 'b3c4d5e6f708' + '9'.repeat(52)

  it('uploaded 態帶帳冊雜湊前 12', async () => {
    const wrapper = await mountWith('uploaded', { offsite_sha256: LEDGER_SHA })
    expect(line(wrapper).text()).toBe('已離機保存 · b3c4d5e6f708…')
  })

  it('後端未給帳冊雜湊時只留狀態，不留空的分隔點', async () => {
    const wrapper = await mountWith('uploaded')
    expect(line(wrapper).text()).toBe('已離機保存')
  })

  it('雜湊只截前 12，全長值不進畫面', async () => {
    const wrapper = await mountWith('uploaded', { offsite_sha256: LEDGER_SHA })
    expect(line(wrapper).text()).not.toContain(LEDGER_SHA)
  })
})
