import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import InstanceGuardHalted from '../InstanceGuardHalted.vue'
import { setLanguage } from '@/i18n'
import { SEAL_PHASE_HALTED, getSealPhase, resetSealPhase } from '@/utils/sealPhase'

// 守衛攔下頁（preservice-pages「單實例守衛攔下頁」）。
//
// 這一頁取代的是「上主機讀日誌、抄 12 碼、改 .env、重啟」。本檔釘的是**契約**：
// 三要件缺一不得送出、送出的形狀、四種回應各自的畫面、鎖自行釋放時頁面要自己
// 轉為已啟動——不是像素。
//
// 逐測卸載（docs/dev/testing.md §4）：本頁掛計時器，殘留元件會讓耗時隨測試序上升。
enableAutoUnmount(afterEach)

const getHaltMock = vi.fn()
const ackMock = vi.fn()
vi.mock('@/api/instanceGuard', () => ({
  getInstanceGuard: vi.fn(),
  getInstanceGuardHalt: (...args) => getHaltMock(...args),
  ackInstanceGuardHalt: (...args) => ackMock(...args),
}))

const getSealStatusMock = vi.fn()
vi.mock('@/api/seal', () => ({
  getSealStatus: (...args) => getSealStatusMock(...args),
  unseal: vi.fn(),
}))

const pushMock = vi.fn()
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: pushMock }),
}))

const SINCE = '2026-09-05T13:50:58Z'

const HOLDER = {
  application_name: 'custodexa-instance-guard',
  pid: 268,
  backend_start: '2026-09-05T13:50:58.169055Z',
  code: '2936aed7c309',
  fingerprint_source: 'pg_stat_activity',
}

const HALTED = {
  state: 'halted',
  since: SINCE,
  holder: HOLDER,
  retry_interval_seconds: 15,
}

const RUNNING = {
  state: 'running',
  since: '',
  holder: null,
  retry_interval_seconds: 15,
}

// 續啟動空窗的形狀：行程關掉攔下期監聽、跑 migration、重新開埠。
// 期間任何請求都是連線被拒——**沒有 response**，不是 503
const connectionRefused = () => {
  const err = new Error('Network Error')
  err.request = {}
  return err
}

const SEAL_UP = { state: 'sealed', generation: 1, instance_guard: { state: 'held', peers: 0 } }

const axiosError = (status, data) => {
  const err = new Error(`HTTP ${status}`)
  err.response = { status, data }
  return err
}

const mountPage = () =>
  mount(InstanceGuardHalted, { global: { plugins: [ElementPlus] } })

// 三要件齊備（勾選、重打碼、管理員帳密）
const fillAllThree = async (wrapper) => {
  wrapper.vm.confirmedPrimaryDown = true
  wrapper.vm.code = HOLDER.code
  wrapper.vm.username = 'admin'
  wrapper.vm.password = 'secret'
  await wrapper.vm.$nextTick()
}

const submitButton = (wrapper) => wrapper.find('.submit-btn')

describe('守衛攔下頁：左欄的狀態與持鎖者', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    resetSealPhase()
    getHaltMock.mockResolvedValue(HALTED)
  })

  it('顯示攔下徽章、起算時間與重試週期，並以等寬字呈現持鎖者四欄', async () => {
    const wrapper = mountPage()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('已攔下')
    expect(text).toContain('每 15 秒重試')
    // 起算時間走 utils/format，不裸印 RFC3339
    expect(text).toContain('2026')
    expect(text).not.toContain(SINCE)

    // 三個欄位名是資料庫欄位名，必須原樣（操作者要與主機日誌逐字比對）
    expect(text).toContain('application_name')
    expect(text).toContain('pid')
    expect(text).toContain('backend_start')
    expect(text).toContain('custodexa-instance-guard')
    expect(text).toContain('268')
    expect(text).toContain(HOLDER.backend_start)
    expect(text).toContain(HOLDER.code)

    // 等寬：讀者要逐字元抄碼，比例字型下 0/O、1/l 分不開
    const holderValues = wrapper.findAll('.holder-rows dd')
    expect(holderValues.length).toBe(4)
    for (const dd of holderValues) {
      expect(dd.classes()).toContain('mono')
    }
    expect(wrapper.find('[data-test="holder-code"]').classes()).toContain('mono')
    // 重打欄同樣等寬
    expect(wrapper.find('.code-input').exists()).toBe(true)
  })

  it('兩項不可逆事實與「停止它即可自動啟動」的指引都在畫面上', async () => {
    const wrapper = mountPage()
    await flushPromises()
    const text = wrapper.text()
    expect(text).toContain('兩個實例同時執行會損壞資料')
    expect(text).toContain('本實例尚未寫入任何資料，這不是資料庫損毀')
    expect(text).toContain('停止它，本實例會自動啟動')
  })

  it('風險事實在文件順序上先於任何輸入控制項', async () => {
    const wrapper = mountPage()
    await flushPromises()
    const html = wrapper.html()
    expect(html.indexOf('risk-callout')).toBeGreaterThan(-1)
    expect(html.indexOf('risk-callout')).toBeLessThan(html.indexOf('el-checkbox'))
    expect(html.indexOf('risk-callout')).toBeLessThan(html.indexOf('code-input'))
  })

  it('降級指紋明示此碼不綁定特定工作階段', async () => {
    getHaltMock.mockResolvedValue({
      ...HALTED,
      holder: { ...HOLDER, fingerprint_source: 'unavailable' },
    })
    const wrapper = mountPage()
    await flushPromises()
    expect(wrapper.text()).toContain('降級碼')
  })

  it('狀態讀取失敗在左欄固定版位誠實呈現，不假裝已啟動', async () => {
    getHaltMock.mockRejectedValue(axiosError(503, { error: '服務不可用' }))
    const wrapper = mountPage()
    await flushPromises()
    expect(wrapper.text()).toContain('讀不到攔下狀態')
    expect(wrapper.text()).toContain('服務不可用')
    // 仍不顯示「已啟動」——讀不到狀態不等於服務已上線
    expect(wrapper.text()).not.toContain('前往登入')
  })

  it('進站即把 halted 發佈給導覽相位（否則守衛不知道要把人留在本頁）', async () => {
    mountPage()
    await flushPromises()
    expect(getSealPhase()).toBe(SEAL_PHASE_HALTED)
  })
})

describe('守衛攔下頁：三要件與送出形狀', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    resetSealPhase()
    getHaltMock.mockResolvedValue(HALTED)
  })

  it('三要件缺任一項按鈕即停用，齊備才可按', async () => {
    const wrapper = mountPage()
    await flushPromises()
    expect(submitButton(wrapper).attributes('disabled')).toBeDefined()

    await fillAllThree(wrapper)
    expect(submitButton(wrapper).attributes('disabled')).toBeUndefined()

    // 逐項拿掉一件，每次都必須回到停用
    const removals = [
      () => { wrapper.vm.confirmedPrimaryDown = false },
      () => { wrapper.vm.code = '   ' },
      () => { wrapper.vm.username = '' },
      () => { wrapper.vm.password = '' },
    ]
    for (const remove of removals) {
      await fillAllThree(wrapper)
      remove()
      await wrapper.vm.$nextTick()
      expect(submitButton(wrapper).attributes('disabled')).toBeDefined()
    }
  })

  it('送出的 payload 恰為四鍵，碼經修剪', async () => {
    ackMock.mockResolvedValue(RUNNING)
    const wrapper = mountPage()
    await flushPromises()
    await fillAllThree(wrapper)
    wrapper.vm.code = `  ${HOLDER.code}  `
    await wrapper.vm.$nextTick()

    await wrapper.vm.submit()
    await flushPromises()

    expect(ackMock).toHaveBeenCalledTimes(1)
    const [payload, config] = ackMock.mock.calls[0]
    expect(payload).toEqual({
      confirmed_primary_down: true,
      code: HOLDER.code,
      username: 'admin',
      password: 'secret',
    })
    // 失敗就近顯示，不走全域 toast（本頁是唯一畫面，toast 飄走就沒地方回頭看）
    expect(config).toEqual({ skipErrorToast: true })
  })

  it('前端不自行比對確認碼：碼與左欄不同也照送（過期的碼只有後端知道）', async () => {
    ackMock.mockResolvedValue(RUNNING)
    const wrapper = mountPage()
    await flushPromises()
    await fillAllThree(wrapper)
    wrapper.vm.code = 'ffffffffffff'
    await wrapper.vm.$nextTick()
    expect(submitButton(wrapper).attributes('disabled')).toBeUndefined()

    await wrapper.vm.submit()
    await flushPromises()
    expect(ackMock.mock.calls[0][0].code).toBe('ffffffffffff')
  })

  it('送出後清除密碼欄（成功與失敗皆然）', async () => {
    ackMock.mockRejectedValue(
      axiosError(401, { code: 'INSTANCE_GUARD_ACK_UNAUTHORIZED', error: 'x' })
    )
    const wrapper = mountPage()
    await flushPromises()
    await fillAllThree(wrapper)
    await wrapper.vm.submit()
    await flushPromises()
    expect(wrapper.vm.password).toBe('')
  })
})

describe('守衛攔下頁：四種送出結果', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    resetSealPhase()
    getHaltMock.mockResolvedValue(HALTED)
    // 預設停在續啟動空窗（連不上），讓「轉場當下的畫面」可被觀察；
    // 需要走到服務答話的案例各自覆寫
    getSealStatusMock.mockRejectedValue(connectionRefused())
  })

  it('200：先轉「啟動中」，服務答得出話之後才是「已啟動，前往登入」', async () => {
    vi.useFakeTimers()
    try {
      ackMock.mockResolvedValue(RUNNING)
      // 續啟動空窗：連線被拒三次之後服務才重新開埠
      getSealStatusMock
        .mockRejectedValueOnce(connectionRefused())
        .mockRejectedValueOnce(connectionRefused())
        .mockRejectedValueOnce(connectionRefused())
        .mockResolvedValue(SEAL_UP)

      const wrapper = mountPage()
      await flushPromises()
      await fillAllThree(wrapper)
      await wrapper.vm.submit()
      await flushPromises()

      // 空窗期：不說「已啟動」，也不把連不上呈現為錯誤
      expect(wrapper.find('[data-test="starting-desc"]').exists()).toBe(true)
      expect(wrapper.find('.goto-login').exists()).toBe(false)
      expect(wrapper.find('[data-test="submit-error"]').exists()).toBe(false)
      expect(wrapper.find('.code-input').exists()).toBe(false)

      // 退避重試直到服務答話
      await vi.advanceTimersByTimeAsync(30000)
      await flushPromises()

      expect(wrapper.text()).toContain('已啟動')
      expect(wrapper.text()).toContain('前往登入')
      expect(getSealStatusMock.mock.calls.length).toBeGreaterThanOrEqual(4)
      // 相位由封印狀態回應決定，不再是 halted（否則「前往登入」會被守衛彈回本頁）
      expect(getSealPhase()).not.toBe(SEAL_PHASE_HALTED)

      await wrapper.find('.goto-login').trigger('click')
      expect(pushMock).toHaveBeenCalledWith('/login')
    } finally {
      vi.useRealTimers()
    }
  })

  it('空窗期輪詢採退避（不是每毫秒打一次），且連不上不計為錯誤', async () => {
    vi.useFakeTimers()
    try {
      ackMock.mockResolvedValue(RUNNING)
      getSealStatusMock.mockRejectedValue(connectionRefused())
      const wrapper = mountPage()
      await flushPromises()
      await fillAllThree(wrapper)
      await wrapper.vm.submit()
      await flushPromises()

      const first = getSealStatusMock.mock.calls.length
      expect(first).toBe(1)
      await vi.advanceTimersByTimeAsync(1000)
      await flushPromises()
      expect(getSealStatusMock.mock.calls.length).toBe(2)
      // 退避：第二次間隔已大於 1 秒
      await vi.advanceTimersByTimeAsync(1000)
      await flushPromises()
      expect(getSealStatusMock.mock.calls.length).toBe(2)

      await vi.advanceTimersByTimeAsync(120000)
      await flushPromises()
      // 30 秒內的固定 1 秒週期會打上百次；退避上限 8 秒，故遠低於此
      expect(getSealStatusMock.mock.calls.length).toBeLessThan(40)
      expect(wrapper.find('[data-test="starting-desc"]').exists()).toBe(true)
      expect(wrapper.find('[data-test="submit-error"]').exists()).toBe(false)
    } finally {
      vi.useRealTimers()
    }
  })

  it('空窗期若守衛又回到攔下，畫面回到確認表單而非停在啟動中', async () => {
    vi.useFakeTimers()
    try {
      ackMock.mockResolvedValue(RUNNING)
      getSealStatusMock.mockResolvedValue({
        state: 'sealed',
        instance_guard: { state: 'halted', peers: 0 },
      })
      const wrapper = mountPage()
      await flushPromises()
      await fillAllThree(wrapper)
      await wrapper.vm.submit()
      await flushPromises()
      await vi.advanceTimersByTimeAsync(2000)
      await flushPromises()

      expect(wrapper.find('.code-input').exists()).toBe(true)
      expect(wrapper.find('[data-test="starting-desc"]').exists()).toBe(false)
    } finally {
      vi.useRealTimers()
    }
  })

  it('409 HOLDER_CHANGED：左欄換新碼、重打欄清空、就近提示以新碼重來', async () => {
    const NEW_HOLDER = { ...HOLDER, pid: 999, code: 'aaaa1111bbbb' }
    ackMock.mockRejectedValue(
      axiosError(409, {
        code: 'INSTANCE_GUARD_HOLDER_CHANGED',
        error: 'holder changed',
        state: 'halted',
        holder: NEW_HOLDER,
        retry_interval_seconds: 15,
      })
    )
    const wrapper = mountPage()
    await flushPromises()
    await fillAllThree(wrapper)
    await wrapper.vm.submit()
    await flushPromises()

    expect(wrapper.find('[data-test="holder-code"]').text()).toBe('aaaa1111bbbb')
    expect(wrapper.text()).toContain('999')
    expect(wrapper.vm.code).toBe('')
    expect(wrapper.find('[data-test="submit-error"]').text()).toContain(
      '持鎖者已變更'
    )
    // 仍在攔下態：表單留著讓人以新碼重來
    expect(wrapper.find('.code-input').exists()).toBe(true)
  })

  it('401：就近顯示帳密錯誤的機器碼譯文，表單留著', async () => {
    ackMock.mockRejectedValue(
      axiosError(401, { code: 'INSTANCE_GUARD_ACK_UNAUTHORIZED', error: 'x' })
    )
    const wrapper = mountPage()
    await flushPromises()
    await fillAllThree(wrapper)
    await wrapper.vm.submit()
    await flushPromises()

    expect(wrapper.find('[data-test="submit-error"]').text()).toContain(
      '管理員帳號或密碼不正確'
    )
    expect(wrapper.find('.code-input').exists()).toBe(true)
  })

  it('429：就近顯示退避訊息（退避是行程內計數，非帳號鎖定）', async () => {
    ackMock.mockRejectedValue(
      axiosError(429, { code: 'INSTANCE_GUARD_ACK_LOCKED', error: 'x' })
    )
    const wrapper = mountPage()
    await flushPromises()
    await fillAllThree(wrapper)
    await wrapper.vm.submit()
    await flushPromises()
    expect(wrapper.find('[data-test="submit-error"]').text()).toContain(
      '嘗試次數過多'
    )
  })

  it('503 UNAVAILABLE：就近顯示並指向環境變數路徑', async () => {
    ackMock.mockRejectedValue(
      axiosError(503, { code: 'INSTANCE_GUARD_ACK_UNAVAILABLE', error: 'x' })
    )
    const wrapper = mountPage()
    await flushPromises()
    await fillAllThree(wrapper)
    await wrapper.vm.submit()
    await flushPromises()
    const text = wrapper.find('[data-test="submit-error"]').text()
    expect(text).toContain('INSTANCE_GUARD_ACK')
    expect(text).toContain('重啟')
  })

  it('409 NOT_HALTED：送出途中鎖已被取得，轉為已啟動而非留一個錯誤', async () => {
    ackMock.mockRejectedValue(
      axiosError(409, { code: 'INSTANCE_GUARD_NOT_HALTED', error: 'x' })
    )
    const wrapper = mountPage()
    await flushPromises()
    await fillAllThree(wrapper)
    await wrapper.vm.submit()
    await flushPromises()
    expect(wrapper.find('[data-test="starting-desc"]').exists()).toBe(true)
    expect(wrapper.find('.code-input').exists()).toBe(false)
  })
})

// 實機演練（takeover-drill 5.1）發現：確認成功後左欄仍停在「已攔下／自 — 起／
// 目前查不到持鎖者細節／兩個實例同時執行會損壞資料」。這一組把「左欄跟著相位走」釘住
describe('守衛攔下頁：左欄跟著相位走', () => {
  const SEAL_UP_WITH_SINCE = {
    state: 'sealed',
    generation: 1,
    instance_guard: { state: 'held', peers: 0, since: '2026-09-05T14:02:11Z' },
  }

  const badgeText = (wrapper) => wrapper.find('[data-test="state-badge"]').text()

  const takeOver = async (wrapper) => {
    await fillAllThree(wrapper)
    await wrapper.vm.submit()
    await flushPromises()
  }

  beforeEach(() => {
    vi.clearAllMocks()
    resetSealPhase()
    getHaltMock.mockResolvedValue(HALTED)
    ackMock.mockResolvedValue(RUNNING)
    getSealStatusMock.mockRejectedValue(connectionRefused())
  })

  it('攔下時：徽章「已攔下」、持鎖者卡與風險警示在場、重試週期另起一行', async () => {
    const wrapper = mountPage()
    await flushPromises()
    expect(badgeText(wrapper)).toBe('已攔下')
    expect(wrapper.find('.holder-card').exists()).toBe(true)
    expect(wrapper.find('.risk-callout').exists()).toBe(true)
    expect(wrapper.find('[data-test="status-retry"]').text()).toContain('每 15 秒重試')
    // 狀態列本身只有徽章＋起算（重試週期不參與這一行的寬度預算）
    expect(wrapper.find('[data-test="status-meta"]').text()).not.toContain('15')
  })

  it('啟動中：徽章改為「啟動中」，不再宣稱已攔下', async () => {
    const wrapper = mountPage()
    await flushPromises()
    await takeOver(wrapper)
    expect(badgeText(wrapper)).toBe('啟動中')
    expect(wrapper.text()).not.toContain('已攔下')
  })

  it('已啟動：徽章成功語意、起算列改為「已於 … 啟動」，持鎖者卡與資料損壞警示消失', async () => {
    getSealStatusMock.mockResolvedValue(SEAL_UP_WITH_SINCE)
    const wrapper = mountPage()
    await flushPromises()
    await takeOver(wrapper)

    expect(badgeText(wrapper)).toBe('已啟動')
    const meta = wrapper.find('[data-test="status-meta"]').text()
    expect(meta).toContain('啟動')
    expect(meta).toContain('2026')
    expect(meta).not.toContain('—')

    // 服務起來之後這四件事都不成立，留在畫面上就是在宣稱服務沒起來
    expect(wrapper.find('.holder-card').exists()).toBe(false)
    expect(wrapper.find('.risk-callout').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('兩個實例同時執行會損壞資料')
    expect(wrapper.text()).not.toContain('目前查不到持鎖者細節')
    expect(wrapper.text()).not.toContain('停止它，本實例會自動啟動')
    expect(wrapper.find('[data-test="status-retry"]').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('已攔下')

    // 標題與副標同步改口
    expect(wrapper.find('.halt-title').text()).toBe('系統已啟動')
    expect(wrapper.find('.halt-subtitle').text()).toBe('本實例已開始提供服務。')
  })

  it('封印狀態沒有守衛起算時間時不捏一個：起算列整列不顯示', async () => {
    getSealStatusMock.mockResolvedValue(SEAL_UP)
    const wrapper = mountPage()
    await flushPromises()
    await takeOver(wrapper)
    expect(badgeText(wrapper)).toBe('已啟動')
    expect(wrapper.find('[data-test="status-meta"]').exists()).toBe(false)
  })
})

describe('守衛攔下頁：輪詢與三語', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    resetSealPhase()
    getHaltMock.mockResolvedValue(HALTED)
    getSealStatusMock.mockResolvedValue(SEAL_UP)
  })

  it('輪詢讀到 running 即轉為「已啟動」（鎖自行釋放，不需任何人操作）', async () => {
    vi.useFakeTimers()
    try {
      const wrapper = mountPage()
      await flushPromises()
      expect(wrapper.text()).toContain('已攔下')

      // 原持鎖工作階段結束，watchdog 取得鎖；續啟動空窗同樣先連不上
      getHaltMock.mockResolvedValue(RUNNING)
      getSealStatusMock
        .mockRejectedValueOnce(connectionRefused())
        .mockResolvedValue(SEAL_UP)
      await vi.advanceTimersByTimeAsync(15000)
      await flushPromises()
      expect(wrapper.find('[data-test="starting-desc"]').exists()).toBe(true)

      await vi.advanceTimersByTimeAsync(5000)
      await flushPromises()
      expect(wrapper.text()).toContain('已啟動')
      expect(wrapper.text()).toContain('前往登入')
      expect(wrapper.find('.code-input').exists()).toBe(false)
      expect(getSealPhase()).not.toBe(SEAL_PHASE_HALTED)

      // 轉為已啟動後不再輪詢攔下端點
      const callsAfter = getHaltMock.mock.calls.length
      await vi.advanceTimersByTimeAsync(60000)
      expect(getHaltMock.mock.calls.length).toBe(callsAfter)
    } finally {
      vi.useRealTimers()
    }
  })

  it('輪詢週期取自後端的重取週期；缺值時回落 15 秒', async () => {
    vi.useFakeTimers()
    try {
      getHaltMock.mockResolvedValue({ ...HALTED, retry_interval_seconds: 0 })
      const wrapper = mountPage()
      await flushPromises()
      expect(wrapper.text()).toContain('每 15 秒重試')
      const before = getHaltMock.mock.calls.length
      await vi.advanceTimersByTimeAsync(15000)
      await flushPromises()
      expect(getHaltMock.mock.calls.length).toBeGreaterThan(before)
    } finally {
      vi.useRealTimers()
    }
  })

  // 相位未知（狀態讀不到）時若停掉輪詢，後端恢復後這一頁就永遠停在舊畫面，
  // 只剩「人自己按重新整理」一條路。首次讀取失敗是攔下期的常態，不是終局
  it('首次與後續狀態讀取失敗仍續輪，後端恢復後自己更新到攔下相位', async () => {
    vi.useFakeTimers()
    try {
      getHaltMock
        .mockRejectedValueOnce(axiosError(503, { error: '服務不可用' }))
        .mockRejectedValueOnce(axiosError(503, { error: '服務不可用' }))
        .mockResolvedValue(HALTED)
      const wrapper = mountPage()
      await flushPromises()
      expect(wrapper.text()).toContain('讀不到攔下狀態')
      expect(wrapper.text()).not.toContain(HOLDER.code)

      // 第二次（退避首格 2 秒）仍失敗
      await vi.advanceTimersByTimeAsync(2000)
      await flushPromises()
      expect(getHaltMock.mock.calls.length).toBe(2)
      expect(wrapper.text()).toContain('讀不到攔下狀態')

      // 第三次（退避次格 3 秒）後端答得出話：畫面自己走到攔下相位並顯示持鎖者
      await vi.advanceTimersByTimeAsync(3000)
      await flushPromises()
      expect(getHaltMock.mock.calls.length).toBe(3)
      expect(wrapper.text()).toContain('已攔下')
      expect(wrapper.text()).toContain(HOLDER.code)
      expect(wrapper.text()).not.toContain('讀不到攔下狀態')

      // 恢復後回到後端給的週期（15 秒），而且**一格只讀一次**——
      // 每次失敗若各留一條輪詢，同一格會讀出兩次以上
      await vi.advanceTimersByTimeAsync(15000)
      await flushPromises()
      expect(getHaltMock.mock.calls.length).toBe(4)
      await vi.advanceTimersByTimeAsync(15000)
      await flushPromises()
      expect(getHaltMock.mock.calls.length).toBe(5)
    } finally {
      vi.useRealTimers()
    }
  })

  // 續啟動途中鎖又被別人搶走：頁面退回確認表單，輪詢也要跟著回來——
  // 這條路徑會先停掉攔下輪詢（轉入續啟動），停了不接回就是另一個死畫面
  it('續啟動途中回到攔下相位時輪詢跟著恢復', async () => {
    vi.useFakeTimers()
    try {
      getHaltMock
        .mockResolvedValueOnce(HALTED)
        .mockResolvedValueOnce(RUNNING)
        .mockResolvedValue(HALTED)
      // 續啟動空窗先連不上（退避一格），下一次探測讀到守衛仍在攔下：鎖在途中被搶走
      getSealStatusMock
        .mockRejectedValueOnce(connectionRefused())
        .mockResolvedValue({
          state: 'sealed',
          generation: 1,
          instance_guard: { state: 'halted' },
        })
      const wrapper = mountPage()
      await flushPromises()
      expect(wrapper.text()).toContain('已攔下')

      await vi.advanceTimersByTimeAsync(15000)
      await flushPromises()
      expect(wrapper.find('[data-test="starting-desc"]').exists()).toBe(true)

      await vi.advanceTimersByTimeAsync(1000)
      await flushPromises()
      expect(wrapper.text()).toContain('已攔下')
      expect(wrapper.find('.code-input').exists()).toBe(true)

      const before = getHaltMock.mock.calls.length
      await vi.advanceTimersByTimeAsync(15000)
      await flushPromises()
      expect(getHaltMock.mock.calls.length).toBe(before + 1)
    } finally {
      vi.useRealTimers()
    }
  })

  it('讀取失敗後按「重新整理」成功即接回攔下相位，輪詢仍在且不重複', async () => {
    vi.useFakeTimers()
    try {
      getHaltMock.mockRejectedValue(axiosError(503, { error: '服務不可用' }))
      const wrapper = mountPage()
      await flushPromises()
      expect(wrapper.text()).toContain('讀不到攔下狀態')

      getHaltMock.mockResolvedValue(HALTED)
      await wrapper.find('.halt-refresh').trigger('click')
      await flushPromises()
      expect(wrapper.text()).toContain('已攔下')

      // 連按不製造第二條輪詢
      await wrapper.find('.halt-refresh').trigger('click')
      await flushPromises()

      // 輪詢確實還活著，且一格只讀一次（多按幾次也不會變兩次）
      const before = getHaltMock.mock.calls.length
      await vi.advanceTimersByTimeAsync(15000)
      await flushPromises()
      expect(getHaltMock.mock.calls.length).toBe(before + 1)
      await vi.advanceTimersByTimeAsync(15000)
      await flushPromises()
      expect(getHaltMock.mock.calls.length).toBe(before + 2)
    } finally {
      vi.useRealTimers()
    }
  })

  it('三語切換不留裸 key', async () => {
    const wrapper = mountPage()
    await flushPromises()
    try {
      setLanguage('en-US')
      await wrapper.vm.$nextTick()
      expect(wrapper.text()).toContain('The system has not started')
      expect(wrapper.text()).toContain('Take over')
      expect(wrapper.text()).toContain('application_name')

      setLanguage('ja-JP')
      await wrapper.vm.$nextTick()
      expect(wrapper.text()).toContain('システムは起動していません')
      expect(wrapper.text()).toContain('引き継ぎの確認')
      expect(wrapper.text()).not.toContain('instanceGuard.')
    } finally {
      setLanguage('zh-TW')
      localStorage.removeItem('ot-lang')
    }
  })
})
