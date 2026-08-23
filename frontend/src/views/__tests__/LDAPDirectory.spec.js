// LDAP 目錄設定頁。
//
// 守的是「設定看起來成功、實際上不生效或外洩憑證」的幾個點：
//   - 密碼是 write-only，留空＝沿用；placeholder 必須說出這件事，否則管理者
//     會以為自己把密碼清空了（或反過來，以為填了空字串就等於清除）；
//   - 位址變更＋留空密碼＝把既有憑證送往新位址，伺服端會拒；前端必須提前講，
//     但**既存無密碼時不得提示**（草稿改 URL 是正常路徑，多餘警語只是噪音）；
//   - 必填驗證只在啟用時套用（欄位不因停用而 disabled，草稿必須存得下去）；
//   - 連線測試的價值全在「失敗在哪一階段」，故階梯必須逐階段呈現；
//   - 撥號失敗只有單一「無法連線」語義＋diagnostic_id——這是刻意的收斂，
//     不可因為「除錯不方便」而在 UI 補回細分原因。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import LDAPDirectory from '../LDAPDirectory.vue'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const getMock = vi.fn()
const updateMock = vi.fn()
const deleteMock = vi.fn()
const testMock = vi.fn()

vi.mock('@/api/ldapDirectory', () => ({
  getLDAPDirectory: (...a) => getMock(...a),
  updateLDAPDirectory: (...a) => updateMock(...a),
  deleteLDAPDirectory: (...a) => deleteMock(...a),
  testLDAPDirectory: (...a) => testMock(...a),
}))

const getLocalAdminCountMock = vi.fn()
vi.mock('@/api/user', () => ({
  getLocalAdminCount: (...a) => getLocalAdminCountMock(...a),
}))

const confirmMock = vi.fn()
vi.mock('element-plus', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    ElMessage: { error: vi.fn(), success: vi.fn(), warning: vi.fn() },
    ElMessageBox: { confirm: (...a) => confirmMock(...a) },
  }
})

const configuredView = (overrides = {}) => ({
  configured: true,
  name: '公司目錄',
  url: 'ldaps://dir.example.com:636',
  bind_dn: 'cn=svc-bind,dc=example,dc=com',
  has_bind_password: true,
  base_dn: 'ou=users,dc=example,dc=com',
  user_filter: '(&(objectClass=user)(sAMAccountName=%s))',
  attr_email: 'mail',
  attr_fullname: 'displayName',
  skip_tls_verify: false,
  enabled: true,
  ...overrides,
})

const axiosError = (status, data) => {
  const err = new Error(`HTTP ${status}`)
  err.response = { status, data }
  return err
}

const mountPage = async () => {
  const wrapper = mount(LDAPDirectory, { global: { plugins: [ElementPlus] } })
  await flushPromises()
  return wrapper
}

const actionButtons = (wrapper) => wrapper.findAll('.action-bar button')
const clickTest = async (wrapper) => {
  await actionButtons(wrapper)[0].trigger('click')
  await flushPromises()
}
const clickSave = async (wrapper) => {
  await actionButtons(wrapper)[1].trigger('click')
  await flushPromises()
}

// el-form-item 的錯誤文案經 refDebounced(validateState, 100) 才渲染
const settleValidationMessage = () => new Promise((resolve) => setTimeout(resolve, 150))

const passwordInput = (wrapper) => wrapper.find('.field-bind-password input')
const urlInput = (wrapper) => wrapper.find('.field-url input')

describe('LDAPDirectory 設定頁', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getMock.mockResolvedValue({ configured: false })
    getLocalAdminCountMock.mockResolvedValue({ count: 2 })
    updateMock.mockResolvedValue(configuredView())
  })

  it('未設定態：狀態為「尚未設定」、密碼欄無沿用語義、無清除勾選', async () => {
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('尚未設定')
    expect(wrapper.text()).toContain('尚無目錄設定')
    expect(passwordInput(wrapper).attributes('placeholder')).toBe('請輸入服務帳號密碼')
    // 沒有已保存的密碼就沒有「清除」這個動作可做
    expect(wrapper.find('.clear-secret').exists()).toBe(false)
    // 未設定時不提供刪除入口（沒有東西可刪）
    expect(wrapper.text()).not.toContain('刪除設定')
  })

  it('已設定態：狀態帶反映**已儲存**的啟用狀態，並帶出三分區的既有值', async () => {
    getMock.mockResolvedValue(configuredView())
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('已啟用')
    expect(wrapper.text()).toContain('刪除設定')
    expect(urlInput(wrapper).element.value).toBe('ldaps://dir.example.com:636')
    expect(wrapper.find('.field-url').exists()).toBe(true)
    // 三分區皆在同一頁常駐可見（不是精靈、不是分頁）
    expect(wrapper.text()).toContain('連線')
    expect(wrapper.text()).toContain('使用者搜尋')
    expect(wrapper.text()).toContain('啟用與顯示名')
  })

  it('已設定但停用：狀態為「已設定，未啟用」而非「尚未設定」', async () => {
    getMock.mockResolvedValue(configuredView({ enabled: false }))
    const wrapper = await mountPage()
    expect(wrapper.text()).toContain('已設定，未啟用')
  })

  it('讀取失敗：以錯誤態呈現，不假裝成「尚未設定」', async () => {
    getMock.mockRejectedValue(axiosError(500, { code: 'INTERNAL_LDAP_DIRECTORY_QUERY' }))
    const wrapper = await mountPage()
    expect(wrapper.text()).toContain('讀取失敗')
    expect(wrapper.text()).not.toContain('尚無目錄設定')
  })

  // 原本只放一則 alert 就宣稱「擋在表單之前」，但儲存鈕照樣可按。
  // 表單此時是空白預設值，既存無 bind 密碼時送出去就會把設定清空
  it('讀取失敗：儲存鈕停用，不讓空白表單覆蓋伺服端現況', async () => {
    getMock.mockRejectedValue(axiosError(500, { code: 'INTERNAL_LDAP_DIRECTORY_QUERY' }))
    const wrapper = await mountPage()

    const save = actionButtons(wrapper)[1]
    expect(save.attributes('disabled')).toBeDefined()
    await save.trigger('click')
    await flushPromises()
    expect(updateMock).not.toHaveBeenCalled()
    // 測試不寫入，留著協助診斷
    expect(actionButtons(wrapper)[0].attributes('disabled')).toBeUndefined()
  })

  // 警示與狀態帶原本逐字相同（標題與內文都是），上下相鄰。
  // 分工＝狀態帶說「發生什麼事、怎麼復原」，警示說「我們停了什麼、為什麼」
  it('讀取失敗：警示與狀態帶不得複述同一句話', async () => {
    getMock.mockRejectedValue(axiosError(500, {}))
    const wrapper = await mountPage()

    const statusHint = '無法讀取現行設定，畫面上的欄位不代表伺服器現況'
    const alertText = wrapper.find('.page-alert').text()
    expect(alertText).toContain('儲存已停用')
    expect(alertText).not.toContain(statusHint)
    expect(wrapper.find('.status-strip').text()).toContain(statusHint)
  })

  // warn 閘只在存檔那一刻確認一次，之後回到本頁就再也看不到風險，
  // 於是本頁頭條（綠色「已啟用」）與傳輸安全頁的判定（列入 at_risk_count）相反
  it('已啟用且位址為明文 ldap://：狀態帶標示明文風險', async () => {
    getMock.mockResolvedValue(configuredView({ url: 'ldap://dir.example.com:389' }))
    const wrapper = await mountPage()
    expect(wrapper.find('.status-strip').text()).toContain('每次登入都會以明文送出 bind 密碼')
  })

  it('ldaps:// 或未啟用時不出明文風險語（不製造假警報）', async () => {
    getMock.mockResolvedValue(configuredView())
    const secure = await mountPage()
    expect(secure.find('.status-strip').text()).not.toContain('明文送出 bind 密碼')

    getMock.mockResolvedValue(
      configuredView({ url: 'ldap://dir.example.com:389', enabled: false })
    )
    const draft = await mountPage()
    expect(draft.find('.status-strip').text()).not.toContain('明文送出 bind 密碼')
  })

  it('密碼 placeholder 依 has_bind_password 切換為「已保存，留空則不修改」', async () => {
    getMock.mockResolvedValue(configuredView())
    const wrapper = await mountPage()
    expect(passwordInput(wrapper).attributes('placeholder')).toBe('已保存，留空則不修改')
  })

  it('has_bind_password=false 時無清除勾選，且 placeholder 回到「請輸入」', async () => {
    getMock.mockResolvedValue(configuredView({ has_bind_password: false }))
    const wrapper = await mountPage()
    expect(wrapper.find('.clear-secret').exists()).toBe(false)
    expect(passwordInput(wrapper).attributes('placeholder')).toBe('請輸入服務帳號密碼')
  })

  it('顯式清除勾選：送出 clear_bind_password=true，且密碼輸入停用避免同時給兩者', async () => {
    getMock.mockResolvedValue(configuredView())
    const wrapper = await mountPage()

    await wrapper.find('.clear-secret input').setValue(true)
    await flushPromises()
    expect(passwordInput(wrapper).attributes('disabled')).toBeDefined()
    expect(wrapper.text()).toContain('既存密碼即被清除且無法還原')

    await clickSave(wrapper)
    expect(updateMock).toHaveBeenCalledTimes(1)
    expect(updateMock.mock.calls[0][0].clear_bind_password).toBe(true)
    expect(updateMock.mock.calls[0][0].bind_password).toBe('')
  })

  // 勾選後欄位雖 disabled，placeholder 原本仍寫「留空則不修改」，
  // 與正下方「儲存後既存密碼即被清除且無法還原」在同一個表單項裡互相打臉
  it('勾選清除後 placeholder 改口，不再說「留空則不修改」', async () => {
    getMock.mockResolvedValue(configuredView())
    const wrapper = await mountPage()

    await wrapper.find('.clear-secret input').setValue(true)
    const placeholder = passwordInput(wrapper).attributes('placeholder')
    expect(placeholder).toBe('儲存後將清除；要改設新密碼請先取消勾選')
    expect(placeholder).not.toContain('留空則不修改')
  })

  it('位址變更且未填密碼：提前提示要重供密碼', async () => {
    getMock.mockResolvedValue(configuredView())
    const wrapper = await mountPage()
    expect(wrapper.text()).not.toContain('目錄位址已變更')

    await urlInput(wrapper).setValue('ldaps://other.example.com:636')
    await flushPromises()
    expect(wrapper.text()).toContain('目錄位址已變更')
  })

  it('位址只是等價寫法（大小寫、預設埠）時不提示', async () => {
    getMock.mockResolvedValue(configuredView({ url: 'ldaps://dir.example.com' }))
    const wrapper = await mountPage()

    await urlInput(wrapper).setValue('LDAPS://Dir.Example.com:636')
    await flushPromises()
    expect(wrapper.text()).not.toContain('目錄位址已變更')
  })

  it('**既存無密碼**時改位址不提示（草稿修正 URL 是正常路徑）', async () => {
    getMock.mockResolvedValue(configuredView({ has_bind_password: false }))
    const wrapper = await mountPage()

    await urlInput(wrapper).setValue('ldaps://other.example.com:636')
    await flushPromises()
    expect(wrapper.text()).not.toContain('目錄位址已變更')
  })

  it('位址變更後填了新密碼即不再提示', async () => {
    getMock.mockResolvedValue(configuredView())
    const wrapper = await mountPage()

    await urlInput(wrapper).setValue('ldaps://other.example.com:636')
    await flushPromises()
    expect(wrapper.text()).toContain('目錄位址已變更')

    await passwordInput(wrapper).setValue('new-secret')
    await flushPromises()
    expect(wrapper.text()).not.toContain('目錄位址已變更')
  })

  it('停用態可存草稿：必填欄位空白仍送出', async () => {
    const wrapper = await mountPage()
    await clickSave(wrapper)
    expect(updateMock).toHaveBeenCalledTimes(1)
    expect(updateMock.mock.calls[0][0].enabled).toBe(false)
  })

  it('切為啟用後必填生效：空白欄位擋下送出並就地顯示必填訊息', async () => {
    const wrapper = await mountPage()

    await wrapper.find('.field-enabled .el-switch').trigger('click')
    await flushPromises()

    await clickSave(wrapper)
    expect(updateMock).not.toHaveBeenCalled()
    expect(wrapper.find('.field-url').classes()).toContain('is-error')
    // Element Plus 的錯誤訊息經 100ms debounce 才進 DOM（validateStateDebounced），
    // 不等就只看得到 is-error class 而看不到文案
    await settleValidationMessage()
    expect(wrapper.text()).toContain('啟用目錄登入時此欄必填')
    // 欄位**不因停用而 disabled**，也不因啟用而鎖住：兩態都可編輯
    expect(urlInput(wrapper).attributes('disabled')).toBeUndefined()
  })

  it('連線測試送出的是**未儲存的表單值**（先測後存）', async () => {
    getMock.mockResolvedValue(configuredView())
    testMock.mockResolvedValue({ success: true, stages: [], matched_count: 0, attr_sample: {} })
    const wrapper = await mountPage()

    await urlInput(wrapper).setValue('ldaps://staging.example.com:636')
    await clickTest(wrapper)

    expect(testMock).toHaveBeenCalledTimes(1)
    expect(testMock.mock.calls[0][0].url).toBe('ldaps://staging.example.com:636')
    expect(updateMock).not.toHaveBeenCalled()
  })

  it('測試成功：逐階段列出通過，並顯示命中筆數與屬性抽樣', async () => {
    getMock.mockResolvedValue(configuredView())
    testMock.mockResolvedValue({
      success: true,
      target: 'ldaps://dir.example.com:636',
      stages: [
        { stage: 'dial', ok: true },
        { stage: 'bind', ok: true },
        { stage: 'search', ok: true },
      ],
      matched_count: 42,
      matched_at_least: false,
      attr_sample: { sampled: true, email_present: true, fullname_present: false },
      reused_stored_password: true,
    })
    const wrapper = await mountPage()
    await clickTest(wrapper)

    const text = wrapper.text()
    expect(text).toContain('連線測試通過')
    expect(text).toContain('連線到目錄')
    expect(text).toContain('服務帳號 bind')
    expect(text).toContain('使用者搜尋')
    expect(wrapper.findAll('.stage-item--ok')).toHaveLength(3)
    expect(wrapper.findAll('.stage-item--fail')).toHaveLength(0)
    expect(text).toContain('搜尋命中 42 筆')
    expect(text).toContain('屬性抽樣')
    expect(text).toContain('本次測試沿用已保存的 bind 密碼')
    // 缺值屬性原本與「測試目標」同色同重，在一片綠色的「通過」
    // 底下讀起來像中性資訊；實際後果是自動建立的帳號會靜默缺該欄位
    expect(wrapper.findAll('.attr-missing')).toHaveLength(1)
    expect(text).toContain('自動建立的帳號會缺少該欄位')
  })

  it('屬性皆有值時不出缺值警語（不製造假警報）', async () => {
    getMock.mockResolvedValue(configuredView())
    testMock.mockResolvedValue({
      success: true,
      stages: [
        { stage: 'dial', ok: true },
        { stage: 'bind', ok: true },
        { stage: 'search', ok: true },
      ],
      matched_count: 3,
      attr_sample: { sampled: true, email_present: true, fullname_present: true },
    })
    const wrapper = await mountPage()
    await clickTest(wrapper)

    expect(wrapper.findAll('.attr-missing')).toHaveLength(0)
    expect(wrapper.text()).not.toContain('自動建立的帳號會缺少該欄位')
  })

  it('達搜尋上限時標示「至少 N 筆」而非謊報精確值', async () => {
    getMock.mockResolvedValue(configuredView())
    testMock.mockResolvedValue({
      success: true,
      stages: [{ stage: 'search', ok: true }],
      matched_count: 1000,
      matched_at_least: true,
      attr_sample: { sampled: false },
    })
    const wrapper = await mountPage()
    await clickTest(wrapper)

    expect(wrapper.text()).toContain('搜尋至少命中 1000 筆')
    expect(wrapper.text()).toContain('無命中項目，未取樣屬性')
  })

  it('撥號失敗：只有單一「無法連線」語義＋檢查清單＋diagnostic_id', async () => {
    getMock.mockResolvedValue(configuredView())
    testMock.mockResolvedValue({
      success: false,
      failed_stage: 'dial',
      code: 'connect_failed',
      diagnostic_id: 'ldaptest-7f3a91',
      stages: [{ stage: 'dial', ok: false, code: 'connect_failed' }],
      matched_count: 0,
      attr_sample: { sampled: false },
    })
    const wrapper = await mountPage()
    await clickTest(wrapper)

    const text = wrapper.text()
    expect(text).toContain('連線測試失敗於「連線到目錄」階段')
    expect(text).toContain('無法連線到目錄伺服器')
    // 粗分類原因只在伺服端日誌：UI 恰好一條失敗語義，不因除錯方便而補回解析度
    expect(wrapper.findAll('.stage-item--fail')).toHaveLength(1)
    expect(text).toContain('ldaptest-7f3a91')
    expect(text).toContain('防火牆')
  })

  it('bind 階段失敗：撥號顯示通過、bind 顯示失敗（部分成功可辨識）', async () => {
    getMock.mockResolvedValue(configuredView())
    testMock.mockResolvedValue({
      success: false,
      failed_stage: 'bind',
      code: 'bind_failed',
      diagnostic_id: 'ldaptest-abc',
      stages: [
        { stage: 'dial', ok: true },
        { stage: 'bind', ok: false, code: 'bind_failed' },
      ],
      matched_count: 0,
      attr_sample: { sampled: false },
    })
    const wrapper = await mountPage()
    await clickTest(wrapper)

    expect(wrapper.findAll('.stage-item--ok')).toHaveLength(1)
    expect(wrapper.findAll('.stage-item--fail')).toHaveLength(1)
    expect(wrapper.text()).toContain('服務帳號 bind 失敗')
    // 撥號沒失敗就不該出現撥號用的檢查清單
    expect(wrapper.text()).not.toContain('防火牆')
  })

  // 原本只 v-for 回應帶回來的階段，撥號失敗時整份清單只剩一行。
  // 分階段回報存在的理由就是讓人看出「走到哪一級、還差幾級」
  it('未執行的階段仍列出並標「未執行」，不從階梯上消失', async () => {
    getMock.mockResolvedValue(configuredView())
    testMock.mockResolvedValue({
      success: false,
      failed_stage: 'dial',
      code: 'connect_failed',
      stages: [{ stage: 'dial', ok: false, code: 'connect_failed' }],
      matched_count: 0,
      attr_sample: { sampled: false },
    })
    const wrapper = await mountPage()
    await clickTest(wrapper)

    // 三階恆在：失敗 1、未執行 2
    expect(wrapper.findAll('.stage-item')).toHaveLength(3)
    expect(wrapper.findAll('.stage-item--fail')).toHaveLength(1)
    expect(wrapper.findAll('.stage-item--skipped')).toHaveLength(2)
    expect(wrapper.text()).toContain('未執行')
    // 未執行不得被畫成失敗
    expect(wrapper.findAll('.stage-item--ok')).toHaveLength(0)
  })

  it('出站政策拒絕：可辨識為政策拒絕而非目標主機狀態', async () => {
    getMock.mockResolvedValue(configuredView())
    testMock.mockResolvedValue({
      success: false,
      failed_stage: 'dial',
      code: 'egress_blocked',
      stages: [{ stage: 'dial', ok: false, code: 'egress_blocked' }],
      matched_count: 0,
      attr_sample: { sampled: false },
    })
    const wrapper = await mountPage()
    await clickTest(wrapper)

    expect(wrapper.text()).toContain('封包並未送出')
    expect(wrapper.text()).not.toContain('無法連線到目錄伺服器')
  })

  it('strict 檔位連測試都被拒：以測試語義的文案呈現，不是「拒絕儲存」', async () => {
    getMock.mockResolvedValue(configuredView())
    testMock.mockRejectedValue(
      axiosError(400, { code: 'VALIDATION_TRANSMISSION_STRICT_REJECT', risks: [] })
    )
    const wrapper = await mountPage()
    await clickTest(wrapper)

    expect(wrapper.text()).toContain('拒絕本次測試')
    // 測試未執行就沒有階梯可看，不得渲染出空的階段清單
    expect(wrapper.findAll('.stage-item')).toHaveLength(0)
  })

  // 儲存才是主要動作，但它原本拿到共用碼那句「設定含不安全傳輸」
  // ——把現象重述一次，沒告訴使用者怎麼辦；而測試路徑早就有專屬文案帶出路
  it('strict 檔位拒存：給的是帶出路的 LDAP 專屬文案，不是通用碼', async () => {
    getMock.mockResolvedValue(configuredView())
    updateMock.mockRejectedValue(
      axiosError(400, { code: 'VALIDATION_TRANSMISSION_STRICT_REJECT', risks: [] })
    )
    const wrapper = await mountPage()
    await clickSave(wrapper)

    const text = wrapper.text()
    expect(text).toContain('拒絕儲存')
    expect(text).toContain('ldaps://')
    // 共用碼的通用譯文只重述現象，不得留在畫面上
    expect(text).not.toContain('拒絕存檔：設定含不安全傳輸')
    // 只重送一次（strict 不進確認迴圈——重送無用）
    expect(updateMock).toHaveBeenCalledTimes(1)
    expect(confirmMock).not.toHaveBeenCalled()
  })

  it('warn 檔位存檔：確認風險後帶 risk_acknowledged 重送', async () => {
    getMock.mockResolvedValue(configuredView())
    updateMock
      .mockRejectedValueOnce(
        axiosError(400, {
          code: 'VALIDATION_TRANSMISSION_ACK_REQUIRED',
          risks: [{ key: 'ldap_plaintext', label: 'LDAP 明文' }],
        })
      )
      .mockResolvedValueOnce(configuredView())
    confirmMock.mockResolvedValue('confirm')

    const wrapper = await mountPage()
    await clickSave(wrapper)

    expect(updateMock).toHaveBeenCalledTimes(2)
    expect(updateMock.mock.calls[0][0].risk_acknowledged).toBe(false)
    expect(updateMock.mock.calls[1][0].risk_acknowledged).toBe(true)
    expect(confirmMock.mock.calls[0][0]).toContain('目錄連線未加密')
  })

  it('存檔驗證 400 帶 field：訊息指得出是哪一欄', async () => {
    getMock.mockResolvedValue(configuredView())
    updateMock.mockRejectedValue(
      axiosError(400, {
        code: 'VALIDATION_LDAP_URL_USERINFO',
        error: '目錄位址不可包含帳號密碼',
        field: 'url',
      })
    )
    const wrapper = await mountPage()
    await clickSave(wrapper)

    expect(wrapper.text()).toContain('目錄位址')
    expect(wrapper.text()).toContain('不可包含帳號密碼')
  })

  it('本地管理員為 0 時出現解封能力警示（與 OIDC 頁同源文案）', async () => {
    getLocalAdminCountMock.mockResolvedValue({ count: 0 })
    const wrapper = await mountPage()
    expect(wrapper.text()).toContain('系統已無本地管理員，解封能力已失')
  })

  it('本地管理員數未知時 fail-safe 退回警語，不靜默', async () => {
    getLocalAdminCountMock.mockRejectedValue(new Error('boom'))
    const wrapper = await mountPage()
    expect(wrapper.text()).toContain('外部登入不取代本地管理員')
  })

  // ── 儲存路徑與未儲存草稿 ─────────────────────────────────────────────────

  // 先前只擋了「讀取失敗」，沒擋「讀取還沒回來」。action-bar 在 el-form
  // 之外，v-loading 遮罩蓋不到儲存鈕；此時表單是空白預設值，送出去就是把
  // 伺服器上的 name／url／bind_dn／base_dn 清成空字串（且回綠色「已儲存」）
  it('讀取尚未回來時儲存鈕即停用，空白表單無法覆蓋伺服端現況', async () => {
    getMock.mockReturnValue(new Promise(() => {}))
    const wrapper = mount(LDAPDirectory, { global: { plugins: [ElementPlus] } })
    await flushPromises()

    const save = actionButtons(wrapper)[1]
    expect(save.attributes('disabled')).toBeDefined()
    await save.trigger('click')
    await flushPromises()
    expect(updateMock).not.toHaveBeenCalled()
  })

  // 三階全過但命中 0 筆＝這份設定一個使用者都登不進來。原本頭條是
  // 綠色「通過」，唯一的線索是次要灰字的「搜尋命中 0 筆」——成功結果裡的壞消息不得與好消息同重
  it('命中 0 筆：頭條改為警示並說出後果，不以綠色「通過」收尾', async () => {
    getMock.mockResolvedValue(configuredView())
    testMock.mockResolvedValue({
      success: true,
      stages: [
        { stage: 'dial', ok: true },
        { stage: 'bind', ok: true },
        { stage: 'search', ok: true },
      ],
      matched_count: 0,
      matched_at_least: false,
      attr_sample: { sampled: false },
    })
    const wrapper = await mountPage()
    await clickTest(wrapper)

    const text = wrapper.text()
    expect(text).toContain('未命中任何使用者')
    expect(text).toContain('所有目錄使用者都會登入失敗')
    expect(wrapper.find('.result-card .el-alert--warning').exists()).toBe(true)
    expect(wrapper.find('.result-card .el-alert--success').exists()).toBe(false)
    // 後果警語已涵蓋「沒命中所以沒取樣」，不再複述
    expect(text).not.toContain('無命中項目，未取樣屬性')
  })

  it('達上限的 matched_at_least 不得被誤判為 0 命中', async () => {
    getMock.mockResolvedValue(configuredView())
    testMock.mockResolvedValue({
      success: true,
      stages: [{ stage: 'search', ok: true }],
      matched_count: 1000,
      matched_at_least: true,
      attr_sample: { sampled: false },
    })
    const wrapper = await mountPage()
    await clickTest(wrapper)

    expect(wrapper.text()).not.toContain('所有目錄使用者都會登入失敗')
    expect(wrapper.find('.result-card .el-alert--success').exists()).toBe(true)
  })

  // 動作列在三張分區卡之後，從頁尾按儲存被驗證擋下時，視窗內毫無變化
  // ——沒有 toast、沒有頁面級警示，紅字在摺線之上，焦點還留在按鈕上
  it('驗證失敗：焦點移到第一個出問題的欄位，而非留在按鈕上', async () => {
    const wrapper = mount(LDAPDirectory, {
      attachTo: document.body,
      global: { plugins: [ElementPlus] },
    })
    await flushPromises()

    await wrapper.find('.field-enabled .el-switch').trigger('click')
    await flushPromises()
    await clickSave(wrapper)

    expect(updateMock).not.toHaveBeenCalled()
    const active = document.activeElement
    expect(active.tagName).toBe('INPUT')
    expect(active).toBe(urlInput(wrapper).element)
    wrapper.unmount()
  })

  // 欄位只是 disabled，先打字再勾選會讓 model 仍留著那串字，於是
  // body 同時帶 bind_password 與 clear_bind_password → 伺服端 400；而畫面上
  // 欄位是灰的，使用者看不出自己「填了」什麼，也無法在不取消勾選下清掉它
  it('先填密碼再勾選清除：送出的 body 不得同時帶兩者', async () => {
    getMock.mockResolvedValue(configuredView())
    const wrapper = await mountPage()

    await passwordInput(wrapper).setValue('typed-then-cleared')
    await wrapper.find('.clear-secret input').setValue(true)
    await flushPromises()

    expect(passwordInput(wrapper).element.value).toBe('')
    await clickSave(wrapper)
    expect(updateMock.mock.calls[0][0].clear_bind_password).toBe(true)
    expect(updateMock.mock.calls[0][0].bind_password).toBe('')
  })

  // 工作流是「先測後存」，結果卡因此會與後續編輯並存；改完 URL 後
  // 上一輪那句綠色「通過」仍在畫面上，讀起來像在替**現在**這份設定背書
  it('測試後又改表單：結果卡聲明已過期', async () => {
    getMock.mockResolvedValue(configuredView())
    testMock.mockResolvedValue({
      success: true,
      stages: [{ stage: 'search', ok: true }],
      matched_count: 5,
      attr_sample: { sampled: true, email_present: true, fullname_present: true },
    })
    const wrapper = await mountPage()
    await clickTest(wrapper)
    expect(wrapper.find('.result-stale').exists()).toBe(false)

    await urlInput(wrapper).setValue('ldaps://elsewhere.example.com:636')
    await flushPromises()
    expect(wrapper.find('.result-stale').exists()).toBe(true)
    expect(wrapper.text()).toContain('不代表目前欄位的設定')
    // 結果本身不清掉：診斷碼與階梯還要拿去轉交維運
    expect(wrapper.text()).toContain('連線測試通過')
  })

  // 整頁表單，切選單或按「重新整理」都會靜默丟掉草稿；重新整理這個
  // 名字聽起來完全無害，實際是以伺服端值覆蓋整份表單
  it('有未儲存變更時：顯示提示，且重新整理需先確認', async () => {
    getMock.mockResolvedValue(configuredView())
    const wrapper = await mountPage()
    expect(wrapper.find('.action-bar__dirty').exists()).toBe(false)

    await urlInput(wrapper).setValue('ldaps://draft.example.com:636')
    await flushPromises()
    expect(wrapper.find('.action-bar__dirty').exists()).toBe(true)

    confirmMock.mockRejectedValue(new Error('cancel'))
    getMock.mockClear()
    await wrapper.findAll('.page-actions button').at(-1).trigger('click')
    await flushPromises()
    // 取消＝草稿留著，不重讀
    expect(getMock).not.toHaveBeenCalled()
    expect(urlInput(wrapper).element.value).toBe('ldaps://draft.example.com:636')
  })

  // 原文案只說「調整傳輸政策等級」，而選單裡沒有任何叫「傳輸政策」
  // 的東西；名字最接近的「安全政策」頁又完全不含傳輸設定——等於指了條死路
  it('strict 拒絕的出路要指得出頁面名稱（與選單逐字一致）', async () => {
    getMock.mockResolvedValue(configuredView())
    updateMock.mockRejectedValue(
      axiosError(400, { code: 'VALIDATION_TRANSMISSION_STRICT_REJECT', risks: [] })
    )
    testMock.mockRejectedValue(
      axiosError(400, { code: 'VALIDATION_TRANSMISSION_STRICT_REJECT', risks: [] })
    )
    const wrapper = await mountPage()

    await clickSave(wrapper)
    expect(wrapper.text()).toContain('「傳輸安全」頁')
    await clickTest(wrapper)
    expect(wrapper.text()).toContain('「傳輸安全」頁')
  })

  // ── 讀取尚未回來時的狀態帶 ───────────────────────────────────────────────

  // 既有規則是「不知道就不能說『尚未設定』」，先前只把它套到 OIDC
  // 的**讀取失敗**上。讀取還沒回來同樣是「不知道」，而狀態帶在 v-loading 的
  // 遮罩之外——實測初次進頁時它以全對比度寫著「尚未設定／目錄使用者無法登入」，
  // 伺服器上卻躺著一份已啟用的設定
  it('讀取尚未回來時：狀態帶不得宣稱「尚未設定」', async () => {
    getMock.mockReturnValue(new Promise(() => {}))
    const wrapper = mount(LDAPDirectory, { global: { plugins: [ElementPlus] } })
    await flushPromises()

    const strip = wrapper.find('.status-strip').text()
    expect(strip).not.toContain('尚未設定')
    expect(strip).not.toContain('尚無目錄設定')
    expect(strip).toContain('讀取中')
    // 也不得反過來假裝已設定：不可出現任何「已啟用／已設定」的斷言
    expect(strip).not.toContain('已啟用')
  })

  it('讀取回來後狀態帶才說出事實，且重新整理期間不退回「讀取中」', async () => {
    getMock.mockResolvedValue(configuredView())
    const wrapper = await mountPage()
    expect(wrapper.find('.status-strip').text()).toContain('已啟用')

    // 重新整理進行中：顯示的是「上一次讀到的事實」（陳舊而非虛構）
    getMock.mockReturnValue(new Promise(() => {}))
    await wrapper.findAll('.page-actions button').at(-1).trigger('click')
    await flushPromises()
    const strip = wrapper.find('.status-strip').text()
    expect(strip).toContain('已啟用')
    expect(strip).not.toContain('尚未設定')
  })

  // 過期聲明原本拿整份 payload 比較，於是切一下「啟用目錄登入」
  // 就喊「請重新測試」——但 enabled 對測試結果毫無影響（後端 probe 強制以
  // Enabled=true 驗證，該欄只入審計）。而「測通了→打開啟用→儲存」正是本頁
  // 最主要的動線，在使用者做對事情的那一刻喊狼來了，只會訓練他略過這條聲明
  it('切換啟用開關不得誤判測試結果過期（改真正影響測試的欄位才算）', async () => {
    getMock.mockResolvedValue(configuredView({ enabled: false }))
    testMock.mockResolvedValue({
      success: true,
      stages: [{ stage: 'search', ok: true }],
      matched_count: 3,
      attr_sample: { sampled: true, email_present: true, fullname_present: true },
    })
    const wrapper = await mountPage()
    await clickTest(wrapper)
    expect(wrapper.find('.result-stale').exists()).toBe(false)

    await wrapper.find('.field-enabled .el-switch').trigger('click')
    await flushPromises()
    expect(wrapper.find('.result-stale').exists()).toBe(false)

    // 反例：base DN 會改變搜尋結果，這一改就必須聲明過期
    const baseDn = wrapper
      .findAll('.el-form-item')
      .find((i) => i.text().includes('base DN'))
      .find('input')
    await baseDn.setValue('ou=other,dc=example,dc=com')
    await flushPromises()
    expect(wrapper.find('.result-stale').exists()).toBe(true)
  })
})
