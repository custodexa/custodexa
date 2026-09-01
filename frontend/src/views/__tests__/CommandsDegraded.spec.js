// 跨會話指令稽核頁的降級呈現與關鍵字搜尋誠實橫幅。
//
// 這兩條守的是同一件事：**降級列不得看起來像空指令，也不得靜默消失**。
// 前者是渲染（空字串／「-」都不行），後者是搜尋涵蓋範圍——keyword 走 `command ILIKE`，
// 降級列的 command 是空字串，永遠不會命中；搜 `rm -rf` 得到 0 筆的稽核員必須被告知。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Commands from '../Commands.vue'
import zhTW from '@/i18n/locales/zh-TW.json'

enableAutoUnmount(afterEach)

// happy-dom 的 MutationObserver 與 el-table key-render-helper 不相容（同 Commands.spec.js）
class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const searchCommandsMock = vi.fn()
const routerPushMock = vi.fn()

vi.mock('@/api/commands', () => ({
  searchCommands: (...args) => searchCommandsMock(...args),
}))

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: routerPushMock }),
}))

const degradedRow = {
  id: 3,
  session_id: 'sess-003',
  user_id: 7,
  asset_id: 3,
  command: '',
  seq: 3,
  executed_at: '2026-06-12T08:02:00Z',
  degraded: true,
  degrade_reason: 'altscreen_round',
}

const plainRow = {
  id: 1,
  session_id: 'sess-001',
  user_id: 7,
  asset_id: 3,
  command: 'ls -la /etc',
  seq: 1,
  executed_at: '2026-06-12T08:00:00Z',
  degraded: false,
  degrade_reason: '',
}

const qualifiedRow = {
  id: 4,
  session_id: 'sess-004',
  user_id: 7,
  asset_id: 3,
  command: 'systemctl restart nginx',
  seq: 4,
  executed_at: '2026-06-12T08:03:00Z',
  degraded: false,
  degrade_reason: 'replay_input_bytes',
}

// 依查詢參數分流：帶 keyword 的是列表查詢，不帶的是降級涵蓋範圍探測
const respondWith = ({ listed = [], probed = [], probeTotal = null, probeFails = false }) => {
  searchCommandsMock.mockImplementation(async (params) => {
    if (params.keyword) return { data: listed, total: listed.length }
    if (probeFails) throw new Error('probe down')
    return { data: probed, total: probeTotal === null ? probed.length : probeTotal }
  })
}

const mountCommands = () => mount(Commands, { global: { plugins: [ElementPlus] } })

describe('Commands 降級列呈現（2.6）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('降級列渲染成狀態列，不是空字串也不是看起來像空指令的符號', async () => {
    searchCommandsMock.mockResolvedValue({ data: [plainRow, degradedRow], total: 2 })

    const wrapper = mountCommands()
    await flushPromises()

    const cell = wrapper.find('[data-test="degraded-command"]')
    expect(cell.exists()).toBe(true)
    const text = cell.text()
    expect(text).toContain(zhTW.commands.degrade.title)
    expect(text).toContain(zhTW.enum.commandDegrade.altscreen_round)
    expect(text.trim()).not.toBe('')
    expect(text.trim()).not.toBe('-')
    for (const forbidden of ['(空)', '解析失敗', '系統錯誤']) {
      expect(text).not.toContain(forbidden)
    }
    // 一般列不受影響
    expect(wrapper.text()).toContain('ls -la /etc')
  })

  it('降級列給出下一步：錄影「可能」保留該時段畫面（不宣稱一定有）', async () => {
    searchCommandsMock.mockResolvedValue({ data: [degradedRow], total: 1 })

    const wrapper = mountCommands()
    await flushPromises()

    const hint = wrapper.find('[data-test="degraded-recording-hint"]')
    expect(hint.text()).toBe(zhTW.commands.degrade.recordingMaybe)
    expect(hint.text()).toContain('可能')
    expect(wrapper.find('[data-test="degraded-seek"]').exists()).toBe(true)
  })

  it('點下一步帶該列的時刻進會話詳情（用該列的時間直接定位回放）', async () => {
    searchCommandsMock.mockResolvedValue({ data: [degradedRow], total: 1 })

    const wrapper = mountCommands()
    await flushPromises()

    await wrapper.find('[data-test="degraded-seek"]').trigger('click')

    expect(routerPushMock).toHaveBeenCalledWith({
      path: '/sessions/sess-003',
      query: { at: '2026-06-12T08:02:00Z' },
    })
  })

  it('限定列（文字已入庫但未經回顯確認）顯示文字＋標記，不與降級列混為一談', async () => {
    searchCommandsMock.mockResolvedValue({ data: [qualifiedRow], total: 1 })

    const wrapper = mountCommands()
    await flushPromises()

    expect(wrapper.find('[data-test="degraded-command"]').exists()).toBe(false)
    const cell = wrapper.find('[data-test="qualified-command"]')
    expect(cell.exists()).toBe(true)
    expect(cell.text()).toContain('systemctl restart nginx')
    expect(cell.text()).toContain(zhTW.commands.degrade.qualifiedTag)
  })

  it('未知原因碼走 default 分支：帶出原碼、不白屏、不顯示裸鍵', async () => {
    searchCommandsMock.mockResolvedValue({
      data: [{ ...degradedRow, degrade_reason: 'brand_new_backend_code' }],
      total: 1,
    })

    const wrapper = mountCommands()
    await flushPromises()

    const cell = wrapper.find('[data-test="degraded-command"]')
    expect(cell.exists()).toBe(true)
    expect(cell.text()).toContain('brand_new_backend_code')
    expect(cell.text()).toContain(zhTW.commands.degrade.title)
    expect(cell.text()).not.toContain('commands.degrade')
  })
})

describe('Commands 關鍵字搜尋誠實橫幅（2.7）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  const searchKeyword = async (wrapper, keyword = 'rm -rf') => {
    wrapper.vm.filters.keyword = keyword
    wrapper.vm.handleSearch()
    await flushPromises()
  }

  it('關鍵字查無資料、但該時間窗有降級列時，橫幅給出精確筆數', async () => {
    respondWith({ listed: [], probed: [plainRow, degradedRow, { ...degradedRow, id: 5 }] })

    const wrapper = mountCommands()
    await flushPromises()
    await searchKeyword(wrapper)

    const banner = wrapper.find('[data-test="degrade-keyword-banner"]')
    expect(banner.exists()).toBe(true)
    expect(banner.text()).toContain('2')
    expect(banner.text()).toContain('關鍵字搜尋不會涵蓋')
    // 探測是「拿掉關鍵字、同一時間窗」的獨立查詢
    expect(searchCommandsMock).toHaveBeenCalledWith({ page: 1, page_size: 200 })
  })

  it('該時間窗確定沒有降級列時不顯示橫幅（不製造常態噪音）', async () => {
    respondWith({ listed: [], probed: [plainRow] })

    const wrapper = mountCommands()
    await flushPromises()
    await searchKeyword(wrapper)

    expect(wrapper.find('[data-test="degrade-keyword-banner"]').exists()).toBe(false)
  })

  it('探測只看得到部分視窗時，文案改為「至少」而非精確筆數', async () => {
    respondWith({ listed: [], probed: [degradedRow], probeTotal: 5000 })

    const wrapper = mountCommands()
    await flushPromises()
    await searchKeyword(wrapper)

    const banner = wrapper.find('[data-test="degrade-keyword-banner"]')
    expect(banner.exists()).toBe(true)
    expect(banner.text()).toContain('至少')
  })

  it('探測失敗時倒向揭露：仍顯示橫幅，但不宣稱筆數', async () => {
    respondWith({ listed: [], probeFails: true })

    const wrapper = mountCommands()
    await flushPromises()
    await searchKeyword(wrapper)

    const banner = wrapper.find('[data-test="degrade-keyword-banner"]')
    expect(banner.exists()).toBe(true)
    expect(banner.text()).toContain(zhTW.commands.degrade.bannerUnknown)
  })

  it('沒有關鍵字時不顯示橫幅（降級列本來就在表格裡）', async () => {
    searchCommandsMock.mockResolvedValue({ data: [degradedRow], total: 1 })

    const wrapper = mountCommands()
    await flushPromises()

    expect(wrapper.find('[data-test="degrade-keyword-banner"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="degraded-command"]').exists()).toBe(true)
  })

  it('橫幅上的「清除關鍵字」按鈕真的清掉關鍵字並重查', async () => {
    respondWith({ listed: [], probed: [degradedRow] })

    const wrapper = mountCommands()
    await flushPromises()
    await searchKeyword(wrapper)

    await wrapper.find('[data-test="degrade-banner-clear"]').trigger('click')
    await flushPromises()

    expect(wrapper.vm.filters.keyword).toBe('')
    expect(wrapper.find('[data-test="degrade-keyword-banner"]').exists()).toBe(false)
  })
})
