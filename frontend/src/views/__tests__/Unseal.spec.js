import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessage } from 'element-plus'
import Unseal from '../Unseal.vue'
import { SUPPORTED_LOCALES, LOCALE_LABELS } from '@/i18n'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

// 封印期解封頁（不需登入即可使用）

const getSealStatusMock = vi.fn()
const unsealMock = vi.fn()
const routerPushMock = vi.fn()

vi.mock('@/api/seal', () => ({
  getSealStatus: (...args) => getSealStatusMock(...args),
  unseal: (...args) => unsealMock(...args),
}))

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: routerPushMock }),
}))

const VALID_KEK = 'NEWKEK1234567890abcdefABCDEF0000'

const statusFixture = (overrides = {}) => ({
  state: 'sealed',
  generation: 0,
  cleanup_pending: false,
  journal_faulted: false,
  timeout_total: 0,
  trusted_proxy: false,
  source_restricted: false,
  initialization_required: false,
  ...overrides,
})

const findButton = (wrapper, text) =>
  wrapper.findAll('button').find((b) => b.text().includes(text))

const mountPage = async () => {
  const wrapper = mount(Unseal, { global: { plugins: [ElementPlus] } })
  await flushPromises()
  return wrapper
}

const materialInputs = (wrapper) => wrapper.findAll('.material-input input')
const adminInputs = (wrapper) => wrapper.findAll('.admin-input input')

// 元件狀態快照（材料清除的斷言打在狀態本體，不只是「畫面看不到」）。
// setup scope 內含 timer handle，其物件圖有環，故序列化時丟棄重複參考
const setupStateDump = (wrapper) => {
  const seen = new WeakSet()
  return JSON.stringify(
    Object.entries(wrapper.vm.$ ? wrapper.vm.$.setupState || {} : {}).map(
      ([, v]) => (v && v.value) ?? v
    ),
    (_key, value) => {
      if (typeof value === 'object' && value !== null) {
        if (seen.has(value)) return undefined
        seen.add(value)
      }
      return value
    }
  )
}

describe('Unseal 狀態呈現（四態）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it.each([
    ['sealed', '已封印'],
    ['unsealing', '解封中'],
    ['unsealed', '已解封'],
    ['sealed-faulted', '已封印（故障）'],
  ])('state=%s 顯示對應徽章', async (state, label) => {
    getSealStatusMock.mockResolvedValue(statusFixture({ state, generation: 3 }))
    const wrapper = await mountPage()

    const badge = wrapper.findComponent({ name: 'ElTag' })
    expect(badge.text()).toBe(label)
    expect(wrapper.text()).toContain('解封世代：3')
  })

  it('已解封時不再提供解封表單，改導向登入', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture({ state: 'unsealed' }))
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('系統已解封，服務已上線')
    expect(materialInputs(wrapper)).toHaveLength(0)
    await findButton(wrapper, '前往登入').trigger('click')
    expect(routerPushMock).toHaveBeenCalledWith('/login')
  })

  it('故障機器碼、journal 故障與待收束各自呈現', async () => {
    getSealStatusMock.mockResolvedValue(
      statusFixture({
        state: 'sealed-faulted',
        fault_code: 'SEAL_INIT_FAILED',
        journal_faulted: true,
        cleanup_pending: true,
        cleanup_generation: 4,
        cleanup_reason: 'stage2-timeout',
        cleanup_started_at: '2026-08-02T00:00:00Z',
      })
    )
    const wrapper = await mountPage()

    // 故障碼一律查譯 apierror，前端不自行詮釋成因
    expect(wrapper.text()).toContain('金鑰是對的，但服務初始化失敗')
    expect(wrapper.text()).toContain('無法寫入審計紀錄，已暫停受理解封')
    expect(wrapper.text()).toContain('第 4 代')
    expect(wrapper.text()).toContain('stage2-timeout')
  })

  it('冷卻中顯示倒數與到期時間（限速類刻意可區分於材料失敗）', async () => {
    getSealStatusMock.mockResolvedValue(
      statusFixture({ cooldown_until: new Date(Date.now() + 90_000).toISOString() })
    )
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('解封嘗試冷卻中')
    expect(wrapper.text()).toMatch(/剩餘 01:(29|30)/)
  })

  it('逾時後顯示「以第一次輸入的材料重試」指引', async () => {
    getSealStatusMock.mockResolvedValue(
      statusFixture({ timeout_total: 1, timeout_retry_hint_code: 'SEAL_STAGE2_TIMEOUT' })
    )
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('之前發生過服務初始化逾時')
    expect(wrapper.text()).toContain('請用第一次輸入的那把金鑰重試')
  })

  it('狀態讀取失敗：明示讀不到，不假裝已解封', async () => {
    getSealStatusMock.mockRejectedValue({
      response: { status: 500, data: { code: 'SEAL_STATUS_UNAVAILABLE' } },
    })
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('讀不到封印狀態')
    expect(wrapper.text()).toContain('讀取封印狀態失敗')
    expect(wrapper.text()).not.toContain('系統已解封，服務已上線')
  })
})

describe('Unseal 初始化與一般解封的視覺區分', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('初始化解封：紅框、專屬標題、不可略過的主金鑰警語與管理員帳密欄', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture({ initialization_required: true }))
    const wrapper = await mountPage()

    expect(wrapper.find('.unseal-card').classes()).toContain('is-initialization')
    expect(wrapper.text()).toContain('初始化解封（全新安裝）')
    expect(wrapper.text()).toContain('你在這裡輸入的內容，會直接成為本系統的主金鑰')
    expect(wrapper.text()).toContain('弄丟主金鑰，全部資料永久救不回')
    // paste-back＋保存確認＋初始管理員憑證
    expect(materialInputs(wrapper)).toHaveLength(2)
    expect(adminInputs(wrapper)).toHaveLength(2)
    expect(wrapper.text()).toContain('管理員帳號與密碼')
  })

  it('一般解封：無紅框、無初始化警語、只要材料一欄', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture({ initialization_required: false }))
    const wrapper = await mountPage()

    expect(wrapper.find('.unseal-card').classes()).not.toContain('is-initialization')
    expect(wrapper.text()).toContain('一般解封')
    expect(wrapper.text()).not.toContain('你在這裡輸入的內容，會直接成為本系統的主金鑰')
    expect(materialInputs(wrapper)).toHaveLength(1)
    expect(adminInputs(wrapper)).toHaveLength(0)
  })

  it('狀態未帶 initialization_required：明示無法判定，不預設任一路徑', async () => {
    const status = statusFixture()
    delete status.initialization_required
    getSealStatusMock.mockResolvedValue(status)
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('請自行選擇解封方式')
    // 預設仍是一般解封（較保守：不會把材料固化為主金鑰），但可顯式切換
    expect(wrapper.find('.unseal-card').classes()).not.toContain('is-initialization')
    await findButton(wrapper, '切換至初始化解封').trigger('click')
    await flushPromises()
    expect(wrapper.find('.unseal-card').classes()).toContain('is-initialization')
  })
})

describe('Unseal 送出', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('一般解封只送 kek 一鍵（多餘鍵會被後端整包拒絕）', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture())
    unsealMock.mockResolvedValue({ state: 'unsealed', generation: 1 })
    const wrapper = await mountPage()

    await materialInputs(wrapper)[0].setValue(VALID_KEK)
    await flushPromises()
    await findButton(wrapper, '送出解封').trigger('click')
    await flushPromises()

    expect(unsealMock).toHaveBeenCalledWith({ kek: VALID_KEK }, { skipErrorToast: true })
    expect(Object.keys(unsealMock.mock.calls[0][0])).toEqual(['kek'])
  })

  it('初始化解封送出 paste-back、保存確認與初始管理員憑證', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture({ initialization_required: true }))
    unsealMock.mockResolvedValue({ state: 'unsealed', generation: 1 })
    const wrapper = await mountPage()

    const [material, confirm] = materialInputs(wrapper)
    await material.setValue(VALID_KEK)
    await confirm.setValue(VALID_KEK)
    const [username, password] = adminInputs(wrapper)
    await username.setValue('admin')
    await password.setValue('pw-12345678')
    const checkbox = wrapper
      .findAllComponents({ name: 'ElCheckbox' })
      .find((c) => c.text().includes('我已經把主金鑰存到'))
    await checkbox.find('input').setValue(true)
    await flushPromises()

    await findButton(wrapper, '送出解封').trigger('click')
    await flushPromises()

    expect(unsealMock).toHaveBeenCalledWith(
      {
        kek: VALID_KEK,
        kek_confirm: VALID_KEK,
        confirm_saved: true,
        username: 'admin',
        password: 'pw-12345678',
      },
      { skipErrorToast: true }
    )
  })

  it('初始化解封：paste-back 不符或未勾保存確認即擋住送出', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture({ initialization_required: true }))
    const wrapper = await mountPage()

    const [material, confirm] = materialInputs(wrapper)
    await material.setValue(VALID_KEK)
    await confirm.setValue(`${VALID_KEK.slice(0, 31)}X`)
    const [username, password] = adminInputs(wrapper)
    await username.setValue('admin')
    await password.setValue('pw-12345678')
    await flushPromises()

    expect(wrapper.text()).toContain('兩次輸入不一樣')
    const submitBtn = findButton(wrapper, '送出解封')
    expect(submitBtn.attributes('disabled')).toBeDefined()
    await submitBtn.trigger('click')
    await flushPromises()
    expect(unsealMock).not.toHaveBeenCalled()
  })

  it('初始化解封的格式不合即時提示；一般解封不套格式檢查（既有 KEK 可能早於格式規則）', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture({ initialization_required: true }))
    const initWrapper = await mountPage()
    await materialInputs(initWrapper)[0].setValue('short')
    await flushPromises()
    expect(initWrapper.text()).toContain('這不是 32 位元組的金鑰')

    getSealStatusMock.mockResolvedValue(statusFixture({ initialization_required: false }))
    const normalWrapper = await mountPage()
    await materialInputs(normalWrapper)[0].setValue('short')
    await flushPromises()
    expect(normalWrapper.text()).not.toContain('這不是 32 位元組的金鑰')
    expect(findButton(normalWrapper, '送出解封').attributes('disabled')).toBeUndefined()
  })

  it('失敗一律走 resolveApiError，不自行推測材料類失敗的成因', async () => {
    const errorSpy = vi.spyOn(ElMessage, 'error')
    getSealStatusMock.mockResolvedValue(statusFixture())
    unsealMock.mockRejectedValue({
      response: { status: 400, data: { code: 'SEAL_MATERIAL_INVALID', error: 'raw backend message' } },
    })
    const wrapper = await mountPage()

    await materialInputs(wrapper)[0].setValue(VALID_KEK)
    await flushPromises()
    await findButton(wrapper, '送出解封').trigger('click')
    await flushPromises()

    expect(errorSpy.mock.calls[0][0]).toBe('解封失敗，送出的內容沒有通過驗證。')
    expect(errorSpy.mock.calls[0][0]).not.toContain('raw backend message')
    // 失敗後重讀狀態：冷卻／退避等限速資訊才會即時反映
    expect(getSealStatusMock).toHaveBeenCalledTimes(2)
  })

  it('429 退避：限速類明確可辨識（與材料失敗刻意不同）', async () => {
    const errorSpy = vi.spyOn(ElMessage, 'error')
    getSealStatusMock.mockResolvedValue(statusFixture())
    unsealMock.mockRejectedValue({
      response: { status: 429, data: { code: 'SEAL_BACKOFF_ACTIVE' } },
    })
    const wrapper = await mountPage()

    await materialInputs(wrapper)[0].setValue(VALID_KEK)
    await flushPromises()
    await findButton(wrapper, '送出解封').trigger('click')
    await flushPromises()

    expect(errorSpy.mock.calls[0][0]).toContain('太密集')
  })

  it('送出後清除材料（元件狀態層；成敗皆清）', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture({ initialization_required: true }))
    unsealMock.mockRejectedValue({
      response: { status: 400, data: { code: 'SEAL_MATERIAL_INVALID' } },
    })
    const wrapper = await mountPage()

    const [material, confirm] = materialInputs(wrapper)
    await material.setValue(VALID_KEK)
    await confirm.setValue(VALID_KEK)
    const [username, password] = adminInputs(wrapper)
    await username.setValue('admin')
    await password.setValue('pw-12345678')
    const checkbox = wrapper
      .findAllComponents({ name: 'ElCheckbox' })
      .find((c) => c.text().includes('我已經把主金鑰存到'))
    await checkbox.find('input').setValue(true)
    await flushPromises()
    // 前置確認：材料確實在元件狀態內，之後的「已清除」才不是空泛的先綠
    expect(setupStateDump(wrapper)).toContain(VALID_KEK)

    await findButton(wrapper, '送出解封').trigger('click')
    await flushPromises()

    const dump = setupStateDump(wrapper)
    expect(dump).not.toContain(VALID_KEK)
    expect(dump).not.toContain('pw-12345678')
  })

  it('本地生成鈕產出合格材料並同時填入 paste-back 欄', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture({ initialization_required: true }))
    const wrapper = await mountPage()

    await findButton(wrapper, '本地生成').trigger('click')
    await flushPromises()

    const [first, second] = materialInputs(wrapper).map((i) => i.element.value)
    expect(first).toMatch(/^[A-Za-z0-9]{32}$/)
    expect(second).toBe(first)
  })

  it('卸載時清除材料（離開頁面不留殘值）', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture())
    const wrapper = await mountPage()
    await materialInputs(wrapper)[0].setValue(VALID_KEK)
    await flushPromises()
    const vm = wrapper.vm
    expect(setupStateDump(wrapper)).toContain(VALID_KEK)

    wrapper.unmount()

    const leaked = JSON.stringify(
      Object.entries(vm.$ ? vm.$.setupState || {} : {}).map(([, v]) => (v && v.value) ?? v)
    )
    expect(leaked).not.toContain(VALID_KEK)
  })
})

// —— 封印期語言切換（i18n「Language selectable while sealed」）——
//
// 封印時本頁是**唯一可達頁面**（其餘路由被守衛導向此處、登入端點回 503）。
// 沒有切換入口，看不懂預設語言的操作者就被卡在一個擋住全部服務的頁面上。
// 斷言刻意打在「頁面主體文字真的換了語言」，不是只有選單標籤變。
describe('Unseal 語言切換', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
  })

  const langDropdown = (wrapper) =>
    wrapper
      .findAllComponents({ name: 'ElDropdown' })
      .find((d) => d.find('.lang-switch-label').exists())

  it('解封頁具語言切換入口，且以當前語言的原生名顯示', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture())
    const wrapper = await mountPage()

    expect(langDropdown(wrapper), '解封頁應有語言切換入口').toBeTruthy()
    expect(wrapper.find('.lang-switch').text()).toContain(LOCALE_LABELS['zh-TW'])
  })

  it.each([
    ['en-US', 'Unseal the System', 'Lose the master key and all data is gone for good'],
    ['ja-JP', 'システムのアンシール', 'マスター鍵を失うと、全データは永久に戻りません'],
  ])('切到 %s：頁面主體文字即時改語言並寫入 ot-lang', async (lang, title, loss) => {
    getSealStatusMock.mockResolvedValue(statusFixture())
    const wrapper = await mountPage()
    expect(wrapper.find('.unseal-title').text()).toBe('系統解封')

    langDropdown(wrapper).vm.$emit('command', lang)
    await wrapper.vm.$nextTick()

    // 標題與遺失警語都換了＝主體內容確實隨語言重繪，非僅選單標籤
    expect(wrapper.find('.unseal-title').text()).toBe(title)
    expect(wrapper.find('.loss-title').text()).toBe(loss)
    expect(localStorage.getItem('ot-lang')).toBe(lang)
  })

  it('三種支援語言全部可選，且當前語言項停用', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture())
    const wrapper = await mountPage()

    langDropdown(wrapper).vm.handleOpen()
    await flushPromises()

    const items = wrapper.findAllComponents({ name: 'ElDropdownItem' })
    expect(items.map((i) => i.text())).toEqual(
      SUPPORTED_LOCALES.map((l) => LOCALE_LABELS[l])
    )
    const current = items.find((i) => i.text() === LOCALE_LABELS['zh-TW'])
    expect(current.props('disabled')).toBe(true)
  })

  it('切換不觸發任何後端呼叫（封印期後端多數端點不可用）', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture())
    const wrapper = await mountPage()
    const callsBefore = getSealStatusMock.mock.calls.length

    langDropdown(wrapper).vm.$emit('command', 'en-US')
    await wrapper.vm.$nextTick()

    expect(getSealStatusMock.mock.calls.length).toBe(callsBefore)
    expect(unsealMock).not.toHaveBeenCalled()
    expect(wrapper.find('.unseal-title').text()).toBe('Unseal the System')
  })
})

// —— 遺失警語的版面優先度（i18n「解封頁文案的操作者可讀性」）——
//
// 舊版是整頁最後一個 12px 註腳；讀者是跳著看的疲勞維運人員，讀不到它。
describe('Unseal 遺失警語', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('未解封時顯示，且排在任何解封表單之前', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture())
    const wrapper = await mountPage()

    const callout = wrapper.find('.loss-callout')
    expect(callout.exists()).toBe(true)
    expect(callout.find('.loss-title').text()).toBe('弄丟主金鑰，全部資料永久救不回')
    expect(callout.text()).toContain('沒有備份金鑰，也沒有任何救援管道')
    // 位置以 DOM 序比較，不以「畫面上看得到」為通過依據
    const html = wrapper.html()
    expect(html.indexOf('loss-callout')).toBeLessThan(html.indexOf('form-section'))
  })

  it('已解封時不顯示（該狀態下不可行動，恆掛只會訓練使用者忽略它）', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture({ state: 'unsealed' }))
    const wrapper = await mountPage()

    expect(wrapper.find('.loss-callout').exists()).toBe(false)
  })

  it('一般解封路徑同樣顯示（該操作者可能是這把金鑰的唯一持有者）', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture({ initialization_required: false }))
    const wrapper = await mountPage()

    expect(wrapper.find('.loss-callout').exists()).toBe(true)
  })

  it('舊的頁尾註腳已移除（否則警語會退回被忽略的位置）', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture())
    const wrapper = await mountPage()

    expect(wrapper.find('.loss-notice').exists()).toBe(false)
  })
})
