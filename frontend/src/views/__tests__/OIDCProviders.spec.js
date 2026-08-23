// OIDC provider 管理頁。
//
// 守的是「設定看起來成功、實際上不生效」的幾個點：
//   - issuer／client_id 編輯時必須停用並說明原因（後端亦強制，前端漏了會讓人白填）；
//   - client_secret 留空＝沿用，不得送出空字串把密鑰洗掉；
//   - issuer_kind 的**判定來源**必須看得見（部署宣告打錯字的唯一可見訊號）；
//   - 停用會推進憑證世代，不可靜默切換。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import OIDCProviders from '../OIDCProviders.vue'

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

const getProvidersMock = vi.fn()
const createProviderMock = vi.fn()
const updateProviderMock = vi.fn()
const deleteProviderMock = vi.fn()

vi.mock('@/api/oidc', () => ({
  getOIDCProviders: (...a) => getProvidersMock(...a),
  createOIDCProvider: (...a) => createProviderMock(...a),
  updateOIDCProvider: (...a) => updateProviderMock(...a),
  deleteOIDCProvider: (...a) => deleteProviderMock(...a),
}))

const getLocalAdminCountMock = vi.fn()
vi.mock('@/api/user', () => ({
  getLocalAdminCount: (...a) => getLocalAdminCountMock(...a),
}))

const LOCAL_ADMIN_NONE_TITLE = '系統已無本地管理員，解封能力已失'
// 主詞是「外部登入」而非「SSO」：不變式涵蓋所有外部身分來源
// （OIDC 與 LDAP 皆然），且本則警語的內文本來就寫「若全部管理員都改為外部登入」
// ——標題說 SSO、內文說外部登入是頁內自相矛盾。與 LDAP 頁同頁面群、同措辭
const LOCAL_ADMIN_FALLBACK_TITLE =
  '外部登入不取代本地管理員：請至少保留一名以本地密碼登入的管理員帳號'

const azure = {
  id: 1,
  name: 'Azure AD',
  issuer: 'https://login.microsoftonline.com/tid-1/v2.0',
  client_id: 'client-1',
  scopes: 'openid profile email',
  admission_mode: 'jit_with_rules',
  admission_rules: '{"tid":["tid-1"],"email_verified":true}',
  enabled: true,
  has_secret: true,
  issuer_kind: 'dedicated',
  issuer_kind_source: 'deploy_declared',
  config_complete: true,
}

const okta = {
  id: 2,
  name: 'Okta',
  issuer: 'https://acme.okta.com',
  client_id: 'client-2',
  scopes: 'openid',
  admission_mode: 'prebound_only',
  admission_rules: '',
  enabled: false,
  has_secret: false,
  issuer_kind: 'shared',
  issuer_kind_source: 'unknown_default',
  config_complete: false,
  incomplete_hint: 'public_base_url_missing',
}

const mountView = () => mount(OIDCProviders, { global: { plugins: [ElementPlus] } })

describe('OIDCProviders 管理頁', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getProvidersMock.mockResolvedValue({ data: [azure, okta] })
    getLocalAdminCountMock.mockResolvedValue({ count: 2 })
  })

  it('列出 provider 並顯示 Issuer 歸屬與判定來源', async () => {
    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('Azure AD')
    expect(text).toContain('本組織專屬')
    expect(text).toContain('部署宣告')
    // 部署宣告未生效的唯一可見訊號
    expect(text).toContain('多組織共用')
    expect(text).toContain('未宣告，保守視為多組織共用')
  })

  // 自述式欄名仍載不動兩個後果：
  // 共用 issuer 上純 Email 網域規則會被拒、准入模式每次登入都重判。
  // 這兩句只存在於表頭 tooltip，掉了不會有任何測試以外的訊號
  it('兩個欄位表頭帶 tooltip 說明後果（Issuer 歸屬、准入模式）', async () => {
    const wrapper = mountView()
    await flushPromises()

    const contents = wrapper
      .findAllComponents({ name: 'ElTooltip' })
      .map((c) => String(c.props('content')))
    expect(contents.some((c) => c.includes('僅憑 Email 網域的准入規則會被拒絕'))).toBe(true)
    expect(contents.some((c) => c.includes('每次登入都重新判定，非僅首次'))).toBe(true)
  })

  // 原本 catch 只 log，畫面照常渲染 EmptyState，於是伺服器出錯時
  // 本頁**主動宣稱**「尚未設定任何 OIDC 提供者」——管理者會以為設定被刪了。
  // LDAP 頁在同一事件上已明確區分兩者；同層的身分來源頁不得給相反的答案
  it('清單讀取失敗：明示讀取失敗，不得謊稱「尚未設定任何提供者」', async () => {
    getProvidersMock.mockRejectedValue(new Error('boom'))
    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('無法讀取提供者清單')
    expect(text).toContain('清單未能載入')
    expect(text).toContain('這不代表尚未設定任何提供者')
    expect(text).not.toContain('尚未設定任何 OIDC 提供者')
  })

  // 先前只修了「讀取失敗」，但「讀取還沒回來」是同一句假話換一條
  // 路徑——清單當下為空的原因是還沒讀到，不是沒有設定。實測延遲 GET 期間畫面
  // 就寫著「尚未設定任何 OIDC 提供者」（在遮罩下仍讀得出來）
  it('讀取尚未回來時：不得謊稱「尚未設定任何提供者」', async () => {
    getProvidersMock.mockReturnValue(new Promise(() => {}))
    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).not.toContain('尚未設定任何 OIDC 提供者')
    expect(text).not.toContain('清單未能載入')
  })

  it('讀取成功且確實為空時，仍走原本的「尚未設定」空狀態', async () => {
    getProvidersMock.mockResolvedValue({ data: [] })
    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('尚未設定任何 OIDC 提供者')
    expect(text).not.toContain('無法讀取提供者清單')
  })

  it('設定不完整者以警示標示並說明成因（該 provider 不會出現在登入頁）', async () => {
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('設定不完整')
    expect(wrapper.text()).toContain('不會出現在登入頁')
    expect(wrapper.text()).toContain('PUBLIC_BASE_URL')
  })

  // 本地管理員警示三態。
  // 舊語義是「常駐提示」，已改為條件式：常駐版在正常部署下是純噪音，
  // 會訓練管理者略過本頁警示區（同區還有「設定不完整」「准入不合規」兩條真警示）
  it('尚有本地管理員時不顯示任何本地管理員警示', async () => {
    getLocalAdminCountMock.mockResolvedValue({ count: 1 })
    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).not.toContain(LOCAL_ADMIN_NONE_TITLE)
    expect(text).not.toContain(LOCAL_ADMIN_FALLBACK_TITLE)
  })

  it('本地管理員歸零時以 error 級不可關閉警示指出解封能力已失', async () => {
    getLocalAdminCountMock.mockResolvedValue({ count: 0 })
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain(LOCAL_ADMIN_NONE_TITLE)
    // 這是已失能的事實而非提醒：不得是 warning、不得可關閉
    const alert = wrapper
      .findAllComponents({ name: 'ElAlert' })
      .find((c) => String(c.props('title')).includes(LOCAL_ADMIN_NONE_TITLE))
    expect(alert).toBeTruthy()
    expect(alert.props('type')).toBe('error')
    expect(alert.props('closable')).toBe(false)
    // 要說出後果與出路，否則管理者無從判斷該做什麼
    expect(wrapper.text()).toContain('封印')
    expect(wrapper.text()).toContain('請立即建立一個本地管理員帳號')
  })

  it('計數讀取失敗時 fail-safe 退回通用警語（狀態未知不裝沒事）', async () => {
    getLocalAdminCountMock.mockRejectedValue(new Error('network down'))
    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain(LOCAL_ADMIN_FALLBACK_TITLE)
    // 未知不等於歸零：不得升級成「已失能」的斷言
    expect(text).not.toContain(LOCAL_ADMIN_NONE_TITLE)
  })

  it('回應缺 count 欄位視同讀取失敗（不得當成安全）', async () => {
    getLocalAdminCountMock.mockResolvedValue({})
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain(LOCAL_ADMIN_FALLBACK_TITLE)
  })

  it('編輯時 issuer／client_id 停用並說明不可變原因', async () => {
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openEditDialog(azure)
    await flushPromises()

    expect(wrapper.vm.isEdit).toBe(true)
    const disabledInputs = wrapper.findAll('input[disabled]').map((i) => i.element.value)
    expect(disabledInputs).toContain('https://login.microsoftonline.com/tid-1/v2.0')
    expect(disabledInputs).toContain('client-1')
    expect(wrapper.text()).toContain('建立後不可變更')
  })

  it('編輯回填 scope 與准入規則；送出時 openid 自動帶入且不送 issuer/client_id', async () => {
    updateProviderMock.mockResolvedValue({})
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openEditDialog(azure)
    await flushPromises()
    expect(wrapper.vm.form.scopeExtras).toEqual(['profile', 'email'])
    expect(wrapper.vm.form.rules.tid).toEqual(['tid-1'])
    expect(wrapper.vm.form.rules.email_verified).toBe(true)

    await wrapper.vm.submitForm()
    await flushPromises()

    expect(updateProviderMock).toHaveBeenCalledTimes(1)
    const [id, payload] = updateProviderMock.mock.calls[0]
    expect(id).toBe(1)
    expect(payload.scopes).toBe('openid profile email')
    expect(payload.issuer).toBeUndefined()
    expect(payload.client_id).toBeUndefined()
    expect(JSON.parse(payload.admission_rules)).toEqual({
      tid: ['tid-1'],
      email_verified: true,
    })
  })

  it('client_secret 留空即不送出該欄（沿用既有密鑰），填了才送', async () => {
    updateProviderMock.mockResolvedValue({})
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openEditDialog(azure)
    await flushPromises()
    await wrapper.vm.submitForm()
    await flushPromises()
    expect(updateProviderMock.mock.calls[0][1].client_secret).toBeUndefined()

    wrapper.vm.form.client_secret = 'rotated-secret'
    await wrapper.vm.submitForm()
    await flushPromises()
    expect(updateProviderMock.mock.calls[1][1].client_secret).toBe('rotated-secret')
  })

  it('自動供應但無任何規則時就近擋下，不打 API', async () => {
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openEditDialog(okta)
    await flushPromises()
    wrapper.vm.form.admission_mode = 'jit_with_rules'
    await wrapper.vm.submitForm()
    await flushPromises()

    expect(updateProviderMock).not.toHaveBeenCalled()
    expect(wrapper.vm.formError).toContain('至少提供一條准入規則')
  })

  it('由規則模式切回「僅限已預先綁定的帳號」時提示語義變更', async () => {
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openEditDialog(azure)
    await flushPromises()
    expect(wrapper.vm.preboundSwitchNotice).toBe(false)

    wrapper.vm.form.admission_mode = 'prebound_only'
    await flushPromises()
    expect(wrapper.vm.preboundSwitchNotice).toBe(true)
    expect(wrapper.text()).toContain('既有已綁定的外部身分不受影響')
  })

  it('Azure 多租戶端點在輸入當下即給明確診斷', async () => {
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openCreateDialog()
    await flushPromises()
    wrapper.vm.form.issuer = 'https://login.microsoftonline.com/common/v2.0'
    await flushPromises()

    expect(wrapper.vm.azureMultiTenantWarning).toContain('租戶專屬的 issuer')
    expect(wrapper.text()).toContain('Microsoft 多租戶端點')

    wrapper.vm.form.issuer = 'https://login.microsoftonline.com/tid-1/v2.0'
    await flushPromises()
    expect(wrapper.vm.azureMultiTenantWarning).toBe('')
  })

  // Element Plus 2.6 起 radio/checkbox 的綁定值是 value 而非 label：寫錯不會報錯，
  // 只會讓表單永遠送出空 scope／預設模式。故此處走真實 DOM 互動而非直接改 form
  it('scope 勾選與准入模式選擇經由 DOM 互動生效', async () => {
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openCreateDialog()
    await flushPromises()
    expect(wrapper.vm.form.scopeExtras).toEqual(['profile', 'email'])

    const profileBox = wrapper
      .findAll('.el-checkbox')
      .find((c) => c.text().includes('profile'))
    await profileBox.find('input').setValue(false)
    await flushPromises()
    expect(wrapper.vm.form.scopeExtras).toEqual(['email'])

    const jitRadio = wrapper
      .findAll('.el-radio')
      .find((r) => r.text().includes('依規則自動供應（JIT）'))
    await jitRadio.find('input').setValue()
    await flushPromises()
    expect(wrapper.vm.form.admission_mode).toBe('jit_with_rules')
    // 規則欄位隨模式出現
    expect(wrapper.text()).toContain('租戶識別（tid）')
  })

  it('建立時送出 issuer 與 client_id', async () => {
    createProviderMock.mockResolvedValue({})
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openCreateDialog()
    await flushPromises()
    Object.assign(wrapper.vm.form, {
      name: 'Google',
      issuer: 'https://accounts.google.com',
      client_id: 'g-client',
      scopeExtras: ['email'],
    })
    await wrapper.vm.submitForm()
    await flushPromises()

    expect(createProviderMock).toHaveBeenCalledTimes(1)
    const payload = createProviderMock.mock.calls[0][0]
    expect(payload.issuer).toBe('https://accounts.google.com')
    expect(payload.client_id).toBe('g-client')
    expect(payload.scopes).toBe('openid email')
    expect(payload.admission_mode).toBe('prebound_only')
  })

  it('停用須先確認（推進憑證世代不可靜默）；取消則還原開關', async () => {
    const { ElMessageBox } = await import('element-plus')
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockRejectedValue('cancel')
    const wrapper = mountView()
    await flushPromises()

    const row = { id: 1, name: 'Azure AD', enabled: false, _statusLoading: false }
    await wrapper.vm.handleEnabledChange(row)
    await flushPromises()

    expect(confirmSpy).toHaveBeenCalled()
    expect(updateProviderMock).not.toHaveBeenCalled()
    expect(row.enabled).toBe(true)
    confirmSpy.mockRestore()
  })

  it('確認後停用送出最小 payload（name 為後端必填）', async () => {
    const { ElMessageBox } = await import('element-plus')
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    updateProviderMock.mockResolvedValue({})
    const wrapper = mountView()
    await flushPromises()

    const row = { id: 1, name: 'Azure AD', enabled: false, _statusLoading: false }
    await wrapper.vm.handleEnabledChange(row)
    await flushPromises()

    expect(updateProviderMock).toHaveBeenCalledWith(1, { name: 'Azure AD', enabled: false })
    confirmSpy.mockRestore()
  })

  it('啟用不需確認', async () => {
    const { ElMessageBox } = await import('element-plus')
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm')
    updateProviderMock.mockResolvedValue({})
    const wrapper = mountView()
    await flushPromises()

    const row = { id: 2, name: 'Okta', enabled: true, _statusLoading: false }
    await wrapper.vm.handleEnabledChange(row)
    await flushPromises()

    expect(confirmSpy).not.toHaveBeenCalled()
    expect(updateProviderMock).toHaveBeenCalledWith(2, { name: 'Okta', enabled: true })
    confirmSpy.mockRestore()
  })

  it('准入規則 JSON 損毀時以空規則開表單，不讓整個對話框開不起來', async () => {
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openEditDialog({ ...azure, admission_rules: '{not-json' })
    await flushPromises()

    expect(wrapper.vm.dialogVisible).toBe(true)
    expect(wrapper.vm.form.rules.tid).toEqual([])
  })

  it('刪除經確認後呼叫 API 並重載', async () => {
    const { ElMessageBox } = await import('element-plus')
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    deleteProviderMock.mockResolvedValue({})
    const wrapper = mountView()
    await flushPromises()
    getProvidersMock.mockClear()

    await wrapper.vm.handleDelete(azure)
    await flushPromises()

    expect(deleteProviderMock).toHaveBeenCalledWith(1)
    expect(getProvidersMock).toHaveBeenCalled()
    confirmSpy.mockRestore()
  })
})

describe('OIDCProviders 切換為「僅限已預先綁定的帳號」的影響面提示', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('提示帶出具體的既有身分數，而非僅語義說明', async () => {
    // 只說「既有身分不受影響」，管理者無從判斷這個切換涉及幾個人
    getProvidersMock.mockResolvedValue({
      data: [{ ...azure, identity_count: 12 }],
    })
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openEditDialog({ ...azure, identity_count: 12 })
    wrapper.vm.form.admission_mode = 'prebound_only'
    await flushPromises()

    expect(wrapper.vm.preboundSwitchNotice).toBe(true)
    expect(wrapper.vm.preboundSwitchDesc).toContain('12')
  })

  it('後端未提供 identity_count 時退回無數字版本，不假裝知道', async () => {
    getProvidersMock.mockResolvedValue({ data: [azure] })
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openEditDialog(azure) // 無 identity_count 欄
    wrapper.vm.form.admission_mode = 'prebound_only'
    await flushPromises()

    expect(wrapper.vm.preboundSwitchNotice).toBe(true)
    expect(wrapper.vm.preboundSwitchDesc).not.toMatch(/\d/)
  })

  it('身分數為 0 時仍顯示數字（0 是有意義的影響面，不可當作缺值）', async () => {
    getProvidersMock.mockResolvedValue({ data: [{ ...azure, identity_count: 0 }] })
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openEditDialog({ ...azure, identity_count: 0 })
    wrapper.vm.form.admission_mode = 'prebound_only'
    await flushPromises()

    expect(wrapper.vm.preboundSwitchDesc).toContain('0')
  })
})

// 「僅限已預先綁定的帳號」的效力**限制** SHALL 於管理介面明示。
// 與「切換語義」提示是兩件不同的事：後者講「切過去之後既有身分會怎樣」，
// 前者講「這個模式擋不住什麼」——只有後者存在時，管理者會誤以為 prebound_only
// 等同於「IdP 端一有異動就自動失效」
describe('OIDCProviders prebound_only 的效力限制明示', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getProvidersMock.mockResolvedValue({ data: [okta] })
  })

  it('選擇「僅限已預先綁定的帳號」時明示「不涵蓋帳號仍存續而組織歸屬已變更」', async () => {
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openCreateDialog() // 預設即 prebound_only
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('「僅限已預先綁定的帳號」的效力限制')
    expect(text).toContain('組織歸屬已變更')
    expect(text).toContain('已離職但帳號保留')
  })

  it('切到依規則自動供應時不顯示該限制（限制只屬於 prebound_only）', async () => {
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openCreateDialog()
    wrapper.vm.form.admission_mode = 'jit_with_rules'
    await flushPromises()

    expect(wrapper.text()).not.toContain('「僅限已預先綁定的帳號」的效力限制')
  })
})

// 准入規則不合規。Issuer 歸屬是現算的：部署層移除某 issuer 的專屬宣告後，
// 原本合法的規則**就地**變成不合規，卻沒有任何寫入、也沒有任何錯誤回應。
// 管理端不標示的話，唯一症狀是「使用者突然無法自動供應而查不到原因」
describe('OIDCProviders 准入規則不合規標示', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('不合規者列上掛徽章，頁面警示點名 provider，成因留在列內 tooltip', async () => {
    // 警示合併為一條：一 provider 一條 full-width alert
    // 與列內 tooltip 逐字重複，三個不合規就把表格推到摺線以下
    getProvidersMock.mockResolvedValue({
      data: [
        { ...azure, admission_compliant: false, admission_issue: 'shared_needs_org_rule' },
      ],
    })
    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('准入規則不合規')
    expect(text).toContain('自動供應已停止')
    // 警示點名是哪個 provider（合併後仍要能指認對象）
    expect(text).toContain('Azure AD')
    // 成因仍可取得，只是收在該列徽章的 tooltip 內
    const tooltipContents = wrapper
      .findAllComponents({ name: 'ElTooltip' })
      .map((c) => c.props('content'))
    expect(tooltipContents.some((c) => String(c).includes('租戶識別'))).toBe(true)
  })

  it('多個不合規時只出一條警示並列出全部名稱（不逐一堆疊）', async () => {
    getProvidersMock.mockResolvedValue({
      data: [
        { ...azure, admission_compliant: false, admission_issue: 'shared_needs_org_rule' },
        { ...okta, admission_compliant: false, admission_issue: 'empty_rule_set' },
      ],
    })
    const wrapper = mountView()
    await flushPromises()

    const alerts = wrapper.findAll('.el-alert').filter((a) => a.text().includes('自動供應已停止'))
    expect(alerts).toHaveLength(1)
    expect(alerts[0].text()).toContain(azure.name)
    expect(alerts[0].text()).toContain(okta.name)
  })

  it('不合規列的准入模式就地標示「已停止」（避免與徽章自相矛盾）', async () => {
    getProvidersMock.mockResolvedValue({
      data: [
        { ...azure, admission_mode: 'jit_with_rules', admission_compliant: false, admission_issue: 'empty_rule_set' },
      ],
    })
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('依規則自動供應（JIT）（已停止）')
    expect(wrapper.vm.admissionTagType({ admission_compliant: false })).toBe('danger')
  })

  it('五個成因機器碼各有專屬文案，未知碼退回通用文案（不顯示裸機器碼）', async () => {
    getProvidersMock.mockResolvedValue({ data: [azure] })
    const wrapper = mountView()
    await flushPromises()

    const texts = [
      'shared_needs_org_rule',
      'empty_rule_set',
      'consumer_tenant',
      'email_needs_verified',
      'unknown_rule',
      'invalid_rules',
    ].map((code) => wrapper.vm.admissionIssueText(code))

    // 六段文案兩兩不同，且都不是機器碼本身
    expect(new Set(texts).size).toBe(6)
    texts.forEach((s) => expect(s).not.toMatch(/[a-z]+_[a-z]+/))

    const unknown = wrapper.vm.admissionIssueText('brand_new_reason')
    expect(unknown).not.toContain('brand_new_reason')
    expect(unknown).toContain('自動供應已停止')
  })

  it('合規者與缺欄的舊後端回應都不標示（只認顯式的 false）', async () => {
    getProvidersMock.mockResolvedValue({
      data: [{ ...azure, admission_compliant: true }, { ...okta }],
    })
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.vm.nonCompliantProviders).toEqual([])
    expect(wrapper.text()).not.toContain('准入規則不合規')
  })
})
