import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import InstanceGuardBanner from '../InstanceGuardBanner.vue'
import { setLanguage } from '@/i18n'

// 逐測卸載（docs/dev/testing.md §4）：殘留元件在 document 上累積會讓單測耗時隨測試序上升
enableAutoUnmount(afterEach)

// 管理者細節端點以 mock 取代：本檔驗的是「粗狀態 → 橫幅顯示／隱藏」與
// 「何時、幾次打細節端點」的契約（那條端點每次呼叫留一列審計讀取，次數就是規格）
const getInstanceGuardMock = vi.fn()
vi.mock('@/api/instanceGuard', () => ({
  getInstanceGuard: (...args) => getInstanceGuardMock(...args),
}))

const SINCE = '2026-08-25T09:22:39Z'
const HELD = { state: 'held', since: SINCE, reason: '', peers: 0 }
const HELD_WITH_PEER = { state: 'held', since: SINCE, reason: '', peers: 1 }
const OVERRIDDEN = { state: 'overridden', since: SINCE, reason: 'ack_startup', peers: 0 }
const LOST_CONTENTION = { state: 'lost', since: SINCE, reason: 'contention', peers: 0 }
const LOST_DB = { state: 'lost', since: SINCE, reason: 'db_unreachable', peers: 0 }

// /instance-guard 全貌（形狀＝backend/internal/api/instance_guard_handler.go 的 InstanceGuardView）
const VIEW = {
  state: 'overridden',
  since: SINCE,
  reason: 'ack_startup',
  instance: { hostname: 'c4a434007105', pid: 47, started_at: SINCE },
  db_session_pid: 6445,
  holder: {
    application_name: 'custodexa-instance-guard',
    pid: 6401,
    backend_start: '2026-08-25T09:10:59.169055Z',
    code: 'ab12cd34ef56',
    fingerprint_source: 'pg_stat_activity',
  },
  ack: 'ab12cd34ef56',
  lost_total: 0,
  peers: 0,
}

const mountBanner = (props) =>
  mount(InstanceGuardBanner, {
    props,
    global: { plugins: [ElementPlus] },
  })

const alertOf = (wrapper) => wrapper.find('[role="alert"]')

describe('InstanceGuardBanner 顯示條件', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getInstanceGuardMock.mockResolvedValue(VIEW)
  })

  it('held 且 peers=0 不渲染；狀態未取得或 state 為空亦不渲染', () => {
    expect(alertOf(mountBanner({ status: HELD, isAdmin: true })).exists()).toBe(false)
    expect(alertOf(mountBanner({ status: null, isAdmin: true })).exists()).toBe(false)
    expect(
      alertOf(mountBanner({ status: { state: '', since: '', reason: '', peers: 0 }, isAdmin: true })).exists()
    ).toBe(false)
    expect(getInstanceGuardMock).not.toHaveBeenCalled()
  })

  // spec「非持鎖狀態的橫幅對所有登入者可見」
  it('overridden 對一般使用者渲染狀態說明與摘要句，且沒有任何關閉鈕', async () => {
    const wrapper = mountBanner({ status: OVERRIDDEN, isAdmin: false })
    await flushPromises()
    const alert = alertOf(wrapper)
    expect(alert.exists()).toBe(true)
    expect(alert.text()).toContain('本實例以確認碼啟動')
    expect(alert.text()).toContain('可能有另一個應用實例')
    // 一般使用者的橫幅沒有任何按鈕：既無關閉鈕，也不暴露細節操作
    expect(alert.findAll('button')).toHaveLength(0)
    expect(alert.find('.el-alert__close-btn').exists()).toBe(false)
    expect(getInstanceGuardMock).not.toHaveBeenCalled()
  })

  it('lost 顯示失鎖與原因（contention／db_unreachable 各自的譯文）', async () => {
    const contention = mountBanner({ status: LOST_CONTENTION, isAdmin: false })
    expect(alertOf(contention).text()).toContain('本實例已失去單實例鎖')
    expect(alertOf(contention).text()).toContain('鎖由另一個工作階段持有')

    const db = mountBanner({ status: LOST_DB, isAdmin: false })
    expect(alertOf(db).text()).toContain('資料庫連線中斷')
  })

  // 摘要句在 db_unreachable 態不得沿用「可能有另一個實例」——那一態沒有第二個
  // 實例的跡象，該找的是資料庫連線；沿用預設句會把讀者往錯的方向送
  it('db_unreachable 的摘要句不主張偵測到另一個實例', () => {
    const db = mountBanner({ status: LOST_DB, isAdmin: false })
    const summary = db.find('[data-test="banner-summary"]').text()
    expect(summary).toContain('資料庫連線中斷')
    expect(summary).toContain('不代表偵測到另一個實例')
    expect(summary).not.toContain('可能有另一個應用實例')

    // 其餘態維持原句（改動只針對 db_unreachable，不是把摘要整段換掉）
    const contention = mountBanner({ status: LOST_CONTENTION, isAdmin: false })
    expect(contention.find('[data-test="banner-summary"]').text()).toContain(
      '可能有另一個應用實例'
    )
    const overridden = mountBanner({ status: OVERRIDDEN, isAdmin: false })
    expect(overridden.find('[data-test="banner-summary"]').text()).toContain(
      '可能有另一個應用實例'
    )
  })

  // 守衛事件的唯一去處是一列稽核紀錄（`instanceGuardAuditSink`，走 AsyncSink）；
  // 對 instance_guard 沒有任何推送通道。摘要句若說「管理者已被告知」，就是把
  // 一個不存在的承擔者寫進畫面，讀者會以為有人在處理而自己不必動作
  it('摘要句不主張已通知任何人：通知就是這道橫幅', () => {
    for (const status of [OVERRIDDEN, LOST_CONTENTION, LOST_DB]) {
      const text = mountBanner({ status, isAdmin: false })
        .find('[data-test="banner-summary"]')
        .text()
      expect(text).not.toContain('已被告知')
      expect(text).toContain('這道橫幅就是通知本身')
    }
  })

  // spec「持鎖實例偵測到對等守衛連線亦顯示橫幅」
  it('held 但 peers=1 亦顯示（持鎖實例偵測到其他實例連線）', () => {
    const wrapper = mountBanner({ status: HELD_WITH_PEER, isAdmin: false })
    expect(alertOf(wrapper).exists()).toBe(true)
    expect(alertOf(wrapper).text()).toContain('偵測到 1 個其他實例')
    // 持鎖實例的 since 是本實例取得鎖的時刻，不是偵測到對等的時刻：標籤要說清楚
    expect(alertOf(wrapper).text()).toContain('本實例持鎖自')
  })

  it('狀態起始時間走 utils/format 的 24 小時制（不裸印 RFC3339）', () => {
    const wrapper = mountBanner({ status: OVERRIDDEN, isAdmin: false })
    // 年月日一定在；秒級 24h 格式由 formatDateTime 決定，這裡只驗不是裸字串
    expect(alertOf(wrapper).text()).toContain('2026')
    expect(alertOf(wrapper).text()).not.toContain('2026-08-25T09:22:39Z')
    // overridden 的 since 就是狀態發生的時刻，用一般的「自 … 起」，不套持鎖標籤
    expect(alertOf(wrapper).text()).toContain('自 2026')
    expect(alertOf(wrapper).text()).not.toContain('本實例持鎖自')
  })

  // spec「狀態回到持鎖即消失」
  it('狀態回到 held 且 peers=0 即消失；再次出現時重新取細節', async () => {
    const wrapper = mountBanner({ status: OVERRIDDEN, isAdmin: true })
    await flushPromises()
    expect(alertOf(wrapper).exists()).toBe(true)
    expect(getInstanceGuardMock).toHaveBeenCalledTimes(1)

    await wrapper.setProps({ status: HELD })
    expect(alertOf(wrapper).exists()).toBe(false)

    await wrapper.setProps({ status: LOST_CONTENTION })
    await flushPromises()
    expect(alertOf(wrapper).exists()).toBe(true)
    expect(getInstanceGuardMock).toHaveBeenCalledTimes(2)
  })
})

describe('InstanceGuardBanner 管理者細節', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getInstanceGuardMock.mockResolvedValue(VIEW)
  })

  // spec「管理者看到完整指紋」
  it('admin 於橫幅出現時恰呼叫一次細節端點，顯示持鎖者三欄＋確認碼、狀態起始時間與本實例識別', async () => {
    const wrapper = mountBanner({ status: OVERRIDDEN, isAdmin: true })
    await flushPromises()
    expect(getInstanceGuardMock).toHaveBeenCalledTimes(1)
    // 失敗不走全域 toast（橫幅內誠實呈現）
    expect(getInstanceGuardMock).toHaveBeenCalledWith({ skipErrorToast: true })

    const text = alertOf(wrapper).text()
    // 持鎖者指紋可讀形式：application_name／pid／backend_start（原樣，供與日誌逐字比對）＋確認碼
    expect(text).toContain('custodexa-instance-guard')
    expect(text).toContain('6401')
    expect(text).toContain('2026-08-25T09:10:59.169055Z')
    expect(text).toContain('ab12cd34ef56')
    // 本實例識別
    expect(text).toContain('c4a434007105')
    expect(text).toContain('47')
    expect(text).toContain('6445')
    // 確認來源與誠實邊界：系統不知道確認者是誰；守衛不防止資料問題
    expect(text).toContain('INSTANCE_GUARD_ACK')
    expect(text).toContain('系統無法識別確認者是誰')
    expect(text).toContain('不會阻止兩個實例同時執行造成的資料問題')
    // 風險句：四類照設計原句，兩個名詞用白話（不是「錄影落地」「封印期留痕」這類工程口語）；
    // 不加設計沒寫的具體機制（哪個實例寫到哪台機器、哪段紀錄會漏，設計沒有主張，介面就不能主張）
    expect(text).toContain('錄影檔儲存與封印期間稽核紀錄的資料問題')
    expect(text).not.toContain('錄影落地')
    expect(text).not.toContain('封印期留痕')
    // 處置
    expect(text).toContain('確認另一個實例已停止')
  })

  it('同一狀態的後續輪詢更新不再打細節端點（介面不對其輪詢）', async () => {
    const wrapper = mountBanner({ status: OVERRIDDEN, isAdmin: true })
    await flushPromises()
    await wrapper.setProps({ status: { ...OVERRIDDEN } })
    await wrapper.setProps({ status: { ...OVERRIDDEN, peers: 1 } })
    await flushPromises()
    expect(getInstanceGuardMock).toHaveBeenCalledTimes(1)
  })

  it('非 admin 不呼叫細節端點', async () => {
    mountBanner({ status: OVERRIDDEN, isAdmin: false })
    await flushPromises()
    expect(getInstanceGuardMock).not.toHaveBeenCalled()
  })

  it('「重新整理」手動再取一次；「隱藏細節」只收合細節，橫幅本體仍在', async () => {
    const wrapper = mountBanner({ status: OVERRIDDEN, isAdmin: true })
    await flushPromises()
    await wrapper.find('.detail-refresh').trigger('click')
    await flushPromises()
    expect(getInstanceGuardMock).toHaveBeenCalledTimes(2)

    await wrapper.find('.detail-toggle').trigger('click')
    expect(wrapper.find('.banner-detail').exists()).toBe(false)
    expect(alertOf(wrapper).exists()).toBe(true)
    expect(alertOf(wrapper).text()).toContain('本實例以確認碼啟動')
  })

  it('細節取得失敗時在橫幅內誠實呈現，橫幅本體不消失', async () => {
    getInstanceGuardMock.mockRejectedValue(new Error('HTTP 500'))
    const wrapper = mountBanner({ status: OVERRIDDEN, isAdmin: true })
    await flushPromises()
    expect(alertOf(wrapper).exists()).toBe(true)
    expect(alertOf(wrapper).text()).toContain('無法取得守衛細節')
  })

  it('降級指紋（fingerprint_source=unavailable）明示確認碼不綁定特定工作階段', async () => {
    getInstanceGuardMock.mockResolvedValue({
      ...VIEW,
      holder: { ...VIEW.holder, fingerprint_source: 'unavailable', application_name: '', backend_start: '' },
    })
    const wrapper = mountBanner({ status: OVERRIDDEN, isAdmin: true })
    await flushPromises()
    expect(alertOf(wrapper).text()).toContain('降級碼')
  })

  it('持鎖實例（held＋peers）的處置句指向確認對方是否該存在，且不顯示本次啟動確認碼', async () => {
    getInstanceGuardMock.mockResolvedValue({ ...VIEW, state: 'held', reason: '', holder: null, ack: '', peers: 1 })
    const wrapper = mountBanner({ status: HELD_WITH_PEER, isAdmin: true })
    await flushPromises()
    const text = alertOf(wrapper).text()
    expect(text).toContain('目前沒有其他工作階段持有鎖')
    expect(text).toContain('確認是否有另一個實例正在執行')
    // 處置句給的是可感知的時長（watchdog ≤30 秒＋前端輪詢 60 秒），不是「驗證週期」
    expect(text).toContain('兩分鐘內')
    expect(text).not.toContain('驗證週期')
    expect(text).not.toContain('本次啟動使用的確認碼')
  })

  it('三語切換不留裸 key', async () => {
    const wrapper = mountBanner({ status: OVERRIDDEN, isAdmin: true })
    await flushPromises()

    setLanguage('en-US')
    await wrapper.vm.$nextTick()
    expect(alertOf(wrapper).text()).toContain('this banner is the notification')
    expect(alertOf(wrapper).text()).toContain('Lock holder')
    // 對等數標籤縮短（長標籤會把值欄擠到日期折行）
    expect(alertOf(wrapper).text()).toContain('Other guard instances')

    setLanguage('ja-JP')
    await wrapper.vm.$nextTick()
    expect(alertOf(wrapper).text()).toContain('このバナー自体が通知です')
    expect(alertOf(wrapper).text()).toContain('ロック保持者')
    expect(alertOf(wrapper).text()).toContain('他のガード対応インスタンス数')
    expect(alertOf(wrapper).text()).not.toContain('instanceGuard.')
  })
})
