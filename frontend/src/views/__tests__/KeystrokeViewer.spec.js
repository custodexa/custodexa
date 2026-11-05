// 鍵盤紀錄檢視頁：無交接物要求重填理由、事件與標記列、竄改警示、重新查看沿用理由、離開即清除。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import { holdKeystrokeView, takeKeystrokeView } from '@/utils/keystrokeView'

enableAutoUnmount(afterEach)
class MutationObserverStub { observe() {} disconnect() {} takeRecords() { return [] } }
vi.stubGlobal('MutationObserver', MutationObserverStub)

const metaMock = vi.fn()
const viewMock = vi.fn()
const sessionMock = vi.fn()
const push = vi.fn()
vi.mock('@/api/keystrokes', () => ({
  getKeystrokeMeta: (...a) => metaMock(...a),
  viewKeystrokes: (...a) => viewMock(...a),
}))
vi.mock('@/api/sessions', () => ({ getSession: (...a) => sessionMock(...a) }))
vi.mock('vue-router', () => ({ useRouter: () => ({ push }), useRoute: () => ({ params: { id: '9' } }) }))

import KeystrokeViewer from '../KeystrokeViewer.vue'

const b64 = (s) => btoa(s)
const ev = (seq, text, over = {}) => ({ seq, t_ms: seq * 1000, at: '2026-11-03T06:02:14Z', kind: 1, source: 'user', blocked: false, data_b64: b64(text), ...over })
const page = (events, over = {}) => ({ events, integrity: 'complete', record_status: 'complete', last_event_ms: 0, ...over })

const mountViewer = () => mount(KeystrokeViewer, { global: { plugins: [ElementPlus], stubs: { teleport: true } }, attachTo: document.body })

beforeEach(() => {
  metaMock.mockReset().mockResolvedValue({ data: { state: 'complete', viewable: true, event_count: 3, byte_size: 100 } })
  viewMock.mockReset(); push.mockReset()
  // GET /sessions/:id 回傳本體即會話物件（不包 data），mock 形態須與真實回應一致
  sessionMock.mockReset().mockResolvedValue({ id: 9, protocol: 'ssh', start_time: '2026-11-03T06:02:11Z', end_time: '2026-11-03T06:19:47Z', user: { username: 'ops-chen' }, asset: { name: 'prod-web-01' } })
})

describe('KeystrokeViewer', () => {
  it('沒有交接物（重新整理）：不發請求、要求重填理由', async () => {
    const w = mountViewer()
    await flushPromises()
    expect(w.find('[data-test="keystroke-reenter"]').exists()).toBe(true)
    expect(viewMock).not.toHaveBeenCalled()
    expect(w.find('[data-test="keystroke-events"]').exists()).toBe(false)
  })

  it('顯示事件、控制字元記號、阻斷標示與平台列', async () => {
    holdKeystrokeView(9, '調查 INC-1', { data: page([ev(0, 'ls\r'), ev(1, 'rm -rf x\r', { blocked: true }), ev(2, '\x03', { source: 'platform' })]), loggedAt: new Date() })
    const w = mountViewer()
    await flushPromises()
    const rows = w.findAll('[data-test="keystroke-event-row"]')
    expect(rows).toHaveLength(3)
    expect(rows[0].text()).toContain('ls')
    expect(rows[0].text()).toContain('<CR>')
    expect(rows[1].text()).toContain('已阻斷、未送出')
    expect(rows[2].text()).toContain('平台')
    expect(rows[2].text()).toContain('^C')
    expect(w.find('[data-test="keystroke-reason-text"]').text()).toBe('調查 INC-1')
  })

  it('逐鍵事件呈現層合併：25 事件加 1 標記 → 3 列；系統列 # 顯示「—」；十六進位同列；表尾全在一頁', async () => {
    const keys = [...'sudo systemctl rest\r'].map((c, i) => ev(i, c)) // 20 筆
    const more = [...'exit\r'].map((c, i) => ev(20 + i, c)) // 5 筆
    const marker = { seq: 25, t_ms: 25, at: '2026-11-03T06:02:14Z', kind: 0x10, source: 'platform', blocked: false, marker: 'end_idle_timeout' }
    holdKeystrokeView(9, 'r', { data: page([...keys, ...more, marker]), loggedAt: new Date() })
    metaMock.mockResolvedValue({ data: { state: 'complete', viewable: true, event_count: 26, byte_size: 100 } })
    const w = mountViewer()
    await flushPromises()
    const rows = w.findAll('[data-test="keystroke-event-row"]')
    expect(rows).toHaveLength(3)
    expect(rows[0].text()).toContain('sudo systemctl rest<CR>')
    expect(rows[0].findAll('div')[0].text()).toBe('1')
    expect(rows[1].findAll('div')[0].text()).toBe('21')
    expect(rows[2].findAll('div')[0].text()).toBe('—')
    expect(w.find('[data-test="keystroke-end"]').text()).toContain('全部在這一頁')
    await w.findAll('.el-radio-button__original-radio')[1].setValue(true)
    await flushPromises()
    expect(w.findAll('[data-test="keystroke-event-row"]')).toHaveLength(3)
    expect(w.findAll('[data-test="keystroke-event-row"]')[1].text()).toContain('65 78 69 74 0D')
  })

  it('標記事件以八個碼三語查譯成系統列，未知碼顯示原碼', async () => {
    const m = (seq, marker) => ({ seq, t_ms: seq, at: '2026-11-03T06:02:14Z', kind: 0x10, source: 'platform', blocked: false, marker })
    holdKeystrokeView(9, 'r', { data: page([m(0, 'end_idle_timeout'), m(1, 'writer_stalled'), m(2, 'brand_new_code')]), loggedAt: new Date() })
    const w = mountViewer()
    await flushPromises()
    const rows = w.findAll('[data-test="keystroke-event-row"]')
    expect(rows[0].text()).toContain('閒置逾時')
    expect(rows[0].text()).toContain('系統')
    expect(rows[1].text()).toContain('寫入停擺')
    expect(rows[2].text()).toContain('brand_new_code')
  })

  it('十六進位切換', async () => {
    holdKeystrokeView(9, 'r', { data: page([ev(0, 'A\r')]), loggedAt: new Date() })
    const w = mountViewer()
    await flushPromises()
    await w.findAll('.el-radio-button__original-radio')[1].setValue(true)
    await flushPromises()
    expect(w.find('[data-test="keystroke-event-row"]').text()).toContain('41 0D')
  })

  it('疑似竄改：顯示驗證通過的前段，並以錯誤警示標明不顯示後段', async () => {
    holdKeystrokeView(9, 'r', { data: page([ev(0, 'ok')], { integrity: 'tampered', failed_segment: 3 }), loggedAt: new Date() })
    const w = mountViewer()
    await flushPromises()
    expect(w.findAll('[data-test="keystroke-event-row"]')).toHaveLength(1)
    expect(w.find('[data-test="keystroke-integrity"]').attributes('data-kind')).toBe('tampered')
    expect(w.find('[data-test="keystroke-tail"]').text()).toContain('無法通過驗證')
    expect(w.find('[data-test="keystroke-integrity"]').text()).toContain('第 4 段')
  })

  it('檔案缺失：換成說明卡，不顯示事件表', async () => {
    holdKeystrokeView(9, 'r', { data: page([], { integrity: 'file_missing' }), loggedAt: new Date() })
    const w = mountViewer()
    await flushPromises()
    expect(w.find('[data-test="keystroke-file-missing"]').exists()).toBe(true)
    expect(w.find('[data-test="keystroke-events"]').exists()).toBe(false)
  })

  it('下一頁沿用同一理由並接在表尾，附頁分隔線', async () => {
    holdKeystrokeView(9, '同一理由', { data: page([ev(0, 'a')], { next_event: 1 }), loggedAt: new Date() })
    viewMock.mockResolvedValue({ data: page([ev(1, 'b')]) })
    const w = mountViewer()
    await flushPromises()
    await w.find('[data-test="keystroke-next"]').trigger('click')
    await flushPromises()
    expect(viewMock).toHaveBeenCalledWith('9', { reason: '同一理由', from_event: 1, limit: 5000 })
    expect(w.findAll('[data-test="keystroke-event-row"]')).toHaveLength(2)
    expect(w.findAll('[data-test="keystroke-page-divider"]')).toHaveLength(2)
    expect(w.find('[data-test="keystroke-pager"]').exists()).toBe(false)
  })

  it('下一頁失敗：已載入的頁保留，錯誤在按鈕原位', async () => {
    holdKeystrokeView(9, 'r', { data: page([ev(0, 'a')], { next_event: 1 }), loggedAt: new Date() })
    viewMock.mockRejectedValue(Object.assign(new Error('x'), { response: { status: 409, data: { code: 'RULE_KEYSTROKE_VAULT_SEALED' } } }))
    const w = mountViewer()
    await flushPromises()
    await w.find('[data-test="keystroke-next"]').trigger('click')
    await flushPromises()
    expect(w.findAll('[data-test="keystroke-event-row"]')).toHaveLength(1)
    expect(w.find('[data-test="keystroke-pager"]').text()).toContain('尚未解封')
  })

  it('紀錄中：重新查看最新內容沿用本次理由從頭重送', async () => {
    holdKeystrokeView(9, '沿用理由', { data: page([ev(0, 'a')], { record_status: 'recording' }), loggedAt: new Date() })
    viewMock.mockResolvedValue({ data: page([ev(0, 'a'), ev(1, 'b')], { record_status: 'recording' }) })
    const w = mountViewer()
    await flushPromises()
    await w.find('[data-test="keystroke-refresh"]').trigger('click')
    await flushPromises()
    expect(viewMock).toHaveBeenCalledWith('9', { reason: '沿用理由', limit: 5000 })
    expect(w.findAll('[data-test="keystroke-event-row"]')).toHaveLength(1) // a、b 同為使用者文字事件，併成一列
  })

  describe('圖形連線（畫稿 D）', () => {
    // kind 0x02 payload：uint32 keysym big-endian＋按放
    const keyB64 = (keysym, pressed) => btoa(String.fromCharCode((keysym >>> 24) & 0xff, (keysym >>> 16) & 0xff, (keysym >>> 8) & 0xff, keysym & 0xff, pressed ? 1 : 0))
    const kev = (seq, keysym, pressed) => ({ seq, t_ms: seq * 100, at: '2026-11-04T01:15:54Z', kind: 2, source: 'user', blocked: false, data_b64: keyB64(keysym, pressed) })
    const rawEv = (seq, text) => ({ seq, t_ms: seq * 100, at: '2026-11-04T01:15:54Z', kind: 3, source: 'user', blocked: false, data_b64: btoa(String.fromCharCode(text.length) + text) })
    const graphicsEvents = () => [
      kev(0, 0xffc2, true), kev(1, 0xffc2, false), // F5
      kev(2, 0xffe1, true), kev(3, 0xffe1, false), // 左 Shift
      kev(4, 0x01004e2d, true), // 中
      kev(5, 0x1008ff13, true), // 查無名稱
      rawEv(6, '1.x'),
      { seq: 7, t_ms: 700, at: '2026-11-04T01:15:54Z', kind: 0x10, source: 'platform', blocked: false, marker: 'end_idle_timeout' },
    ]
    const mountGraphics = async (protocol = 'rdp') => {
      sessionMock.mockResolvedValue({ id: 9, protocol, start_time: '2026-11-04T01:15:02Z', user: { username: 'fin-wu' }, asset: { name: 'win-ap-02' } })
      metaMock.mockResolvedValue({ data: { state: 'complete', viewable: true, event_count: 8, byte_size: 100 } })
      holdKeystrokeView(9, 'r', { data: page(graphicsEvents()), loggedAt: new Date() })
      const w = mountViewer()
      await flushPromises()
      return w
    }

    it('不出現模式切換與記號說明列；工具列為按鍵事件範圍與「顯示按鍵代碼」勾選框；欄位為動作／按鍵', async () => {
      const w = await mountGraphics()
      expect(w.find('[data-test="keystroke-mode"]').exists()).toBe(false)
      expect(w.find('.legend').exists()).toBe(false)
      expect(w.text()).not.toContain('可讀文字')
      const bar = w.find('[data-test="keystroke-graphics-toolbar"]')
      expect(bar.text()).toContain('按鍵事件')
      expect(bar.text()).toContain('第 1–8 筆，共 8 筆')
      expect(bar.text()).toContain('顯示按鍵代碼')
      const head = w.find('.ev-head').text()
      expect(head).toContain('動作')
      expect(head).toContain('按鍵')
      expect(head).not.toContain('來源')
      expect(w.find('[data-test="keystroke-integrity"]').text()).toContain('共 8 筆事件；圖形桌面只記按鍵，不記滑鼠')
    })

    it('一個事件一列：按下與放開分兩列，放開列淡一階；名稱正確；系統列 # 為「—」', async () => {
      const w = await mountGraphics()
      const rows = w.findAll('[data-test="keystroke-event-row"]')
      expect(rows).toHaveLength(8)
      const key = (i) => rows[i].find('[data-test="keystroke-key"]').text()
      const act = (i) => rows[i].find('[data-test="keystroke-action"]').text()
      expect([act(0), key(0)]).toEqual(['按下', 'F5'])
      expect([act(1), key(1)]).toEqual(['放開', 'F5'])
      expect(rows[1].classes()).toContain('rel')
      expect(rows[0].classes()).not.toContain('rel')
      expect([act(2), key(2)]).toEqual(['按下', '左 Shift'])
      expect(key(4)).toBe('中（U+4E2D）')
      // 第一層不顯示代碼
      expect(rows[0].find('[data-test="keystroke-key-hex"]').exists()).toBe(false)
      expect(rows[0].find('[data-test="keystroke-key-x11"]').exists()).toBe(false)
      expect(rows[7].findAll('div')[0].text()).toBe('—')
      expect(rows[7].text()).toContain('閒置逾時')
      expect(rows[0].findAll('div')[0].text()).toBe('1')
    })

    it('查無名稱：「未知按鍵」虛線膠囊，不論勾選與否都顯示數值', async () => {
      const w = await mountGraphics()
      const row = () => w.findAll('[data-test="keystroke-event-row"]')[5]
      expect(row().find('[data-test="keystroke-key"]').text()).toBe('未知按鍵')
      expect(row().find('[data-test="keystroke-key"]').classes()).toContain('unknown')
      expect(row().find('[data-test="keystroke-key-hex"]').text()).toBe('0x1008ff13')
      await w.find('[data-test="keystroke-show-codes"] input').setValue(true)
      expect(row().find('[data-test="keystroke-key-hex"]').text()).toBe('0x1008ff13')
      expect(row().find('[data-test="keystroke-key-x11"]').exists()).toBe(false)
    })

    it('勾選「顯示按鍵代碼」：名稱旁多出 X11 名稱與十六進位，且不寫瀏覽器儲存', async () => {
      const before = [localStorage.length, sessionStorage.length]
      const w = await mountGraphics('vnc')
      await w.find('[data-test="keystroke-show-codes"] input').setValue(true)
      const rows = w.findAll('[data-test="keystroke-event-row"]')
      const codes = (i) => [rows[i].find('[data-test="keystroke-key-x11"]').text(), rows[i].find('[data-test="keystroke-key-hex"]').text()]
      expect(codes(0)).toEqual(['F5', '0xffc2'])
      expect(codes(2)).toEqual(['Shift_L', '0xffe1'])
      expect(codes(4)).toEqual(['U4E2D', '0x01004e2d'])
      expect([localStorage.length, sessionStorage.length]).toEqual(before)
    })

    it('0x03 無法解析的原始資料：「未知按鍵」＋原始參數十六進位，動作欄「—」', async () => {
      const w = await mountGraphics()
      const row = w.findAll('[data-test="keystroke-event-row"]')[6]
      expect(row.find('[data-test="keystroke-key"]').text()).toBe('未知按鍵')
      expect(row.find('[data-test="keystroke-key-hex"]').text()).toBe('31 2E 78')
      expect(row.find('[data-test="keystroke-action"]').exists()).toBe(false)
      expect(row.findAll('div')[3].text()).toBe('—')
    })

    it('連線摘要取不到時以事件種類判定為圖形版面', async () => {
      sessionMock.mockRejectedValue(new Error('x'))
      holdKeystrokeView(9, 'r', { data: page([kev(0, 0xffc2, true)]), loggedAt: new Date() })
      const w = mountViewer()
      await flushPromises()
      expect(w.find('[data-test="keystroke-graphics-toolbar"]').exists()).toBe(true)
      expect(w.find('[data-test="keystroke-mode"]').exists()).toBe(false)
    })
  })

  it('文字協定維持原版面（模式切換與記號說明列）', async () => {
    holdKeystrokeView(9, 'r', { data: page([ev(0, 'a')]), loggedAt: new Date() })
    const w = mountViewer()
    await flushPromises()
    expect(w.find('[data-test="keystroke-mode"]').exists()).toBe(true)
    expect(w.find('.legend').exists()).toBe(true)
    expect(w.find('[data-test="keystroke-graphics-toolbar"]').exists()).toBe(false)
  })

  it('離開即清除：卸載後交接物不存在', async () => {
    holdKeystrokeView(9, 'r', { data: page([ev(0, 'a')]), loggedAt: new Date() })
    const w = mountViewer()
    await flushPromises()
    w.unmount()
    expect(takeKeystrokeView(9)).toBeNull()
  })

  it('不寫瀏覽器儲存', async () => {
    const before = [localStorage.length, sessionStorage.length]
    holdKeystrokeView(9, 'r', { data: page([ev(0, 'secret')]), loggedAt: new Date() })
    mountViewer()
    await flushPromises()
    expect([localStorage.length, sessionStorage.length]).toEqual(before)
  })
})
