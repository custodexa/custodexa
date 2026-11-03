import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessage } from 'element-plus'
import AssetExecutorSection from '@/components/asset/AssetExecutorSection.vue'
import ExecutorLoginCheck from '@/components/asset/ExecutorLoginCheck.vue'
import ExecutorReadRuleHelp from '@/components/asset/ExecutorReadRuleHelp.vue'
import { setCapabilitiesForTests, resetCapabilities } from '@/composables/useCapabilities'
import { setPreviewOverlay, clearPreviewOverlay } from '@/utils/previewOverlay'
import { EDIT_FOCUS_TARGETS } from '@/constants/assetExecutor'
import zhTW from '@/i18n/locales/zh-TW.json'

// 專用帳號區塊的測試登入狀態行：填進 login-status 插槽，區塊本身的行為不變。

enableAutoUnmount(afterEach)

class ObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() { return [] }
}
vi.stubGlobal('MutationObserver', ObserverStub)
vi.stubGlobal('ResizeObserver', ObserverStub)

const getMock = vi.fn()
const getCheckMock = vi.fn()
const runCheckMock = vi.fn()
const exportMock = vi.fn()
vi.mock('@/api/assetExecutor', () => ({
  getAssetExecutor: (...a) => getMock(...a),
  deleteAssetExecutor: vi.fn(),
  exportAssetExecutorPublicKey: (...a) => exportMock(...a),
  putAssetExecutor: vi.fn(),
  getExecutorLoginCheck: (...a) => getCheckMock(...a),
  runExecutorLoginCheck: (...a) => runCheckMock(...a),
}))
vi.mock('@/api/assetAccounts', () => ({ listAssetAccounts: vi.fn().mockResolvedValue({ data: [] }) }))
vi.mock('@/api/credentials', () => ({ listCredentials: vi.fn().mockResolvedValue({ data: [] }) }))

const generated = (over = {}) => ({
  configured: true,
  account_id: 7,
  username: 'cx-exec',
  secret_type: 'ssh_key',
  source: 'generate',
  credential: { credential_id: 31, credential_name: 'web-01 / cx-exec', shared_credential: false, binding_count: 1 },
  has_public_key: true,
  fingerprint: 'SHA256:abcd',
  ...over,
})
const state = (over = {}) => ({
  tested: true, stale: false, success: true, code: '', method: 'executor_sudo_nopasswd',
  inventory_read: 'not_needed', checked_at: '2026-11-02T16:58:00', ...over,
})

const mountSection = (props = {}) =>
  mount(AssetExecutorSection, {
    global: { plugins: [ElementPlus] },
    props: { assetId: 5, assetName: 'web-01', protocol: 'ssh', windowsFamily: false, hostKeyRecorded: true, ...props },
    slots: {
      'login-status': (slot) => [h(ExecutorLoginCheck, { ...slot })],
      'setup-help-read-rule': () => [h(ExecutorReadRuleHelp)],
    },
    attachTo: document.body,
  })

import { h } from 'vue'

const deferred = () => {
  let resolve
  let reject
  const promise = new Promise((res, rej) => { resolve = res; reject = rej })
  return { promise, resolve, reject }
}

// 說明分兩行：第一句跟在粗體首句後，其餘另起一行
const bodyOf = (w) => [w.find('[data-test="login-check-body-first"]'), w.find('[data-test="login-check-rest"]')]
  .filter((x) => x.exists()).map((x) => x.text()).join('')
const btn = (w) => w.get('[data-test="login-check-button"]')

beforeEach(() => {
  vi.clearAllMocks()
  setCapabilitiesForTests(['asset:executor-manage', 'credential:create', 'credential:bind', 'credential:update'])
  getMock.mockResolvedValue(generated())
  getCheckMock.mockResolvedValue({ tested: false, stale: false, success: false, code: '', method: '', inventory_read: '' })
})
afterEach(() => resetCapabilities())

describe('ExecutorLoginCheck 狀態行', () => {
  it('未測過：黃框、尚未確認、主要樣式的「測試登入」鈕，位在帳號資訊之下、憑證庫連結之上', async () => {
    const w = mountSection()
    await flushPromises()
    const box = w.get('[data-test="login-check-box"]')
    expect(box.attributes('data-state')).toBe('untested')
    expect(box.classes()).toContain('is-warning')
    expect(w.get('[data-test="login-check-head"]').text()).toBe('尚未確認能登入')
    expect(bodyOf(w)).toBe('到主機加上公鑰並設定 sudo 後，按「測試登入」確認。')
    expect(btn(w).text()).toBe('測試登入')
    expect(btn(w).classes()).toContain('el-button--primary')
    const html = w.html()
    expect(html.indexOf('data-test="executor-info-list"') >= 0 || html.indexOf('cx-exec') >= 0).toBe(true)
    expect(html.indexOf('data-test="login-check"')).toBeLessThan(html.indexOf('data-test="executor-credential-line"'))
  })

  it('已過期（掛載或憑證已變）與未測過同一個畫面', async () => {
    getCheckMock.mockResolvedValue(state({ stale: true }))
    const w = mountSection()
    await flushPromises()
    expect(w.get('[data-test="login-check-box"]').attributes('data-state')).toBe('untested')
  })

  it('非產生金鑰的來源與密碼型用各自的下一步句', async () => {
    getMock.mockResolvedValue(generated({ source: 'shared', has_public_key: false }))
    let w = mountSection()
    await flushPromises()
    expect(bodyOf(w)).toBe('按「測試登入」確認平台登得進去，也能提權改密。')
    getMock.mockResolvedValue(generated({ source: 'inline', secret_type: 'password', has_public_key: false }))
    w = mountSection()
    await flushPromises()
    expect(bodyOf(w)).toBe('到主機設定 sudo 規則後，按「測試登入」確認。')
  })

  it('上次成功：綠框、時間與帳號、「再測一次」；讀不到規則時多一行與設定方式連結', async () => {
    getCheckMock.mockResolvedValue(state({ inventory_read: 'denied' }))
    const w = mountSection()
    await flushPromises()
    const box = w.get('[data-test="login-check-box"]')
    expect(box.classes()).toContain('is-success')
    expect(w.get('[data-test="login-check-head"]').text()).toBe('可以登入')
    expect(bodyOf(w)).toBe('11-02 16:58 測試：能以 cx-exec 登入，也能提權改密。')
    expect(w.get('[data-test="login-check-second"]').text()).toContain('主機帳號盤點的結果會標示「可能不完整」')
    expect(w.find('[data-test="login-check-read-setup"]').exists()).toBe(true)
    expect(btn(w).text()).toBe('再測一次')
    expect(btn(w).classes()).not.toContain('el-button--primary')
  })

  it('成功且 inventory_read 為 not_needed 或 not_checked 時不多出一行；ok 顯示完整句', async () => {
    getCheckMock.mockResolvedValue(state({ method: 'executor_root', inventory_read: 'not_needed' }))
    let w = mountSection()
    await flushPromises()
    expect(w.find('[data-test="login-check-second"]').exists()).toBe(false)
    expect(bodyOf(w)).toContain('本身就有改密權限')
    getCheckMock.mockResolvedValue(state({ inventory_read: 'ok' }))
    w = mountSection()
    await flushPromises()
    expect(w.get('[data-test="login-check-second"]').text()).toContain('主機帳號盤點會是完整的')
    expect(w.find('[data-test="login-check-read-setup"]').exists()).toBe(false)
  })

  it('上次失敗：紅框、該碼的文案、下一步與「再測一次」在同一行', async () => {
    getCheckMock.mockResolvedValue(state({ success: false, code: 'RULE_EXECUTOR_CHECK_LOGIN_FAILED', method: '' }))
    const w = mountSection()
    await flushPromises()
    expect(w.get('[data-test="login-check-box"]').classes()).toContain('is-danger')
    expect(w.get('[data-test="login-check-head"]').text()).toBe('登不進去')
    expect(bodyOf(w)).toContain('主機拒絕了 cx-exec 的金鑰。')
    // 畫面稿：第一句跟在粗體首句後，下一步另起一行
    expect(w.get('[data-test="login-check-body-first"]').text()).toBe('主機拒絕了 cx-exec 的金鑰。')
    expect(w.get('[data-test="login-check-rest"]').text()).toMatch(/^確認公鑰已加到主機上/)
    expect(w.get('[data-test="login-check-fix"]').text()).toBe('取得公鑰')
    expect(btn(w).text()).toBe('再測一次')
    expect(w.get('[data-test="login-check-actions"]').findAll('button')).toHaveLength(2)
  })

  it('九個結果碼都有專屬文案，且各自的下一步正確', async () => {
    const expected = {
      RULE_EXECUTOR_CHECK_CONNECTION_FAILED: [null, '連不到這台主機'],
      RULE_EXECUTOR_CHECK_LOGIN_FAILED: ['取得公鑰', '登不進去'],
      RULE_EXECUTOR_CHECK_HOST_KEY_MISMATCH: ['查看主機金鑰', '主機的身分指紋和記錄不同'],
      RULE_EXECUTOR_CHECK_HOST_KEY_CHECK_FAILED: [null, '無法核對主機的身分指紋'],
      RULE_EXECUTOR_CHECK_ESCALATION_DENIED: [null, '登得進去，但不能改密'],
      RULE_EXECUTOR_CHECK_ESCALATION_NEEDS_NOPASSWD: [null, '登得進去，但不能改密'],
      RULE_EXECUTOR_CHECK_UNAVAILABLE: ['更換', '專用帳號目前沒有可用的秘密'],
      RULE_EXECUTOR_CHECK_ROTATION_PENDING: ['前往憑證庫', '專用帳號正在改密'],
      RULE_EXECUTOR_CHECK_TIMEOUT: [null, '主機沒有在時間內回應'],
    }
    for (const [code, [fix, head]] of Object.entries(expected)) {
      getCheckMock.mockResolvedValue(state({ success: false, code, method: '' }))
      const w = mountSection()
      await flushPromises()
      expect(w.get('[data-test="login-check-head"]').text(), code).toBe(head)
      const fixBtn = w.find('[data-test="login-check-fix"]')
      expect(fixBtn.exists() ? fixBtn.text() : null, code).toBe(fix)
      expect(w.find('[data-test="login-check-raw-code"]').exists(), code).toBe(false)
      w.unmount()
    }
  })

  it('不能改密的兩個碼帶「設定方式」連結，按下以錨點開說明彈出框', async () => {
    getCheckMock.mockResolvedValue(state({ success: false, code: 'RULE_EXECUTOR_CHECK_ESCALATION_DENIED', method: '' }))
    const w = mountSection()
    await flushPromises()
    const setup = w.get('[data-test="login-check-setup"]')
    await setup.trigger('click')
    await flushPromises()
    const popover = w.get('[data-test="executor-help-popover"]')
    expect(popover.text()).toContain('這個帳號要怎麼準備')
    // 讀取 sudo 規則段由插槽填入，且帶逐字照抄的必讀警告
    expect(popover.get('[data-test="login-check-read-rule-example"]').text()).toBe(
      'cx-exec ALL=(root) NOPASSWD: /bin/tar -cf - -C /etc sudoers sudoers.d',
    )
    expect(popover.get('[data-test="login-check-read-rule-warning"]').text()).toContain('TAR_OPTIONS')
  })

  it('密碼型登入被拒：文案改寫成「拒絕了密碼」，修正動作改為更換', async () => {
    getMock.mockResolvedValue(generated({ secret_type: 'password', source: 'inline', has_public_key: false }))
    getCheckMock.mockResolvedValue(state({ success: false, code: 'RULE_EXECUTOR_CHECK_LOGIN_FAILED', method: '' }))
    const w = mountSection()
    await flushPromises()
    expect(bodyOf(w)).toBe('主機拒絕了 cx-exec 的密碼。')
    expect(w.get('[data-test="login-check-fix"]').text()).toBe('更換')
  })

  it('未知結果碼：通用說明，原碼只在第二層', async () => {
    getCheckMock.mockResolvedValue(state({ success: false, code: 'RULE_EXECUTOR_CHECK_FUTURE', method: '' }))
    const w = mountSection()
    await flushPromises()
    expect(w.get('[data-test="login-check-head"]').text()).toBe('測試沒有通過')
    expect(w.get('[data-test="login-check-text"]').text()).not.toContain('RULE_EXECUTOR_CHECK_FUTURE')
    expect(w.get('[data-test="login-check-raw-code"]').text()).toContain('RULE_EXECUTOR_CHECK_FUTURE')
  })

  it('讀不到上次結果（GET 失敗）時當作沒測過，不跳錯誤、按鈕仍可用', async () => {
    getCheckMock.mockRejectedValue({ response: { status: 500 } })
    const w = mountSection()
    await flushPromises()
    expect(w.get('[data-test="login-check-box"]').attributes('data-state')).toBe('untested')
    expect(btn(w).attributes('disabled')).toBeUndefined()
    expect(w.find('[data-test="login-check-error"]').exists()).toBe(false)
  })
})

describe('ExecutorLoginCheck 按下測試', () => {
  it('按下後按鈕停用、狀態行轉為測試中；結果回來後原地換成對應碼的文案，全域訊息函式呼叫 0 次', async () => {
    const msgs = [vi.spyOn(ElMessage, 'success'), vi.spyOn(ElMessage, 'error'), vi.spyOn(ElMessage, 'warning')]
    const d = deferred()
    runCheckMock.mockReturnValue(d.promise)
    const w = mountSection()
    await flushPromises()
    await btn(w).trigger('click')
    expect(runCheckMock).toHaveBeenCalledWith(5)
    // 測試中用 aria-disabled 而非原生 disabled，焦點才不會掉到 body
    expect(btn(w).attributes('disabled')).toBeUndefined()
    expect(btn(w).attributes('aria-disabled')).toBe('true')
    expect(btn(w).attributes('aria-busy')).toBe('true')
    expect(btn(w).text()).toBe('測試中...')
    expect(w.get('[data-test="login-check-box"]').attributes('data-state')).toBe('testing')
    expect(w.get('[data-test="login-check-head"]').text()).toBe('測試中')
    expect(bodyOf(w)).toBe('正在以 cx-exec 登入這台，並檢查改密所需的提權。')
    // 測試中再按一次不會重複發送
    await btn(w).trigger('click')
    expect(runCheckMock).toHaveBeenCalledTimes(1)
    d.resolve({ success: false, code: 'RULE_EXECUTOR_CHECK_ESCALATION_DENIED', method: '', inventory_read: 'not_checked', account_username: 'cx-exec', checked_at: '2026-11-02T16:58:00', stale: false })
    await flushPromises()
    expect(w.get('[data-test="login-check-head"]').text()).toBe('登得進去，但不能改密')
    expect(bodyOf(w)).toContain('cx-exec 沒有改其他帳號密碼所需的 sudo 權限')
    expect(btn(w).attributes('disabled')).toBeUndefined()
    expect(btn(w).attributes('aria-disabled')).toBeUndefined()
    expect(btn(w).attributes('aria-busy')).toBeUndefined()
    expect(btn(w).text()).toBe('再測一次')
    msgs.forEach((m) => expect(m).not.toHaveBeenCalled())
    msgs.forEach((m) => m.mockRestore())
  })

  it('重測：成功後再按，結果換成新的一次（失敗後也能再測成功）', async () => {
    getCheckMock.mockResolvedValue(state({ success: false, code: 'RULE_EXECUTOR_CHECK_TIMEOUT', method: '' }))
    runCheckMock.mockResolvedValue({ success: true, code: '', method: 'executor_sudo_nopasswd', inventory_read: 'ok', checked_at: '2026-11-02T17:10:00', stale: false })
    const w = mountSection()
    await flushPromises()
    expect(w.get('[data-test="login-check-head"]').text()).toBe('主機沒有在時間內回應')
    await btn(w).trigger('click')
    await flushPromises()
    expect(w.get('[data-test="login-check-box"]').classes()).toContain('is-success')
    expect(bodyOf(w)).toContain('11-02 17:10')
    expect(w.find('[data-test="login-check-fix"]').exists()).toBe(false)
  })

  it('被擋的 HTTP 錯誤（429）就地顯示在按鈕旁，不動狀態行、不跳全域提示', async () => {
    const err = vi.spyOn(ElMessage, 'error')
    runCheckMock.mockRejectedValue({ response: { status: 429, data: { code: 'RULE_EXECUTOR_CHECK_RATE_LIMITED' } } })
    const w = mountSection()
    await flushPromises()
    await btn(w).trigger('click')
    await flushPromises()
    expect(w.get('[data-test="login-check-error"]').text()).toBe('測試太頻繁，請稍後再試。')
    expect(w.get('[data-test="login-check-box"]').attributes('data-state')).toBe('untested')
    expect(err).not.toHaveBeenCalled()
    err.mockRestore()
  })

  it('專用帳號已被換掉（409 STATE_CHANGED）：重讀區塊，不跳全域提示', async () => {
    runCheckMock.mockRejectedValue({ response: { status: 409, data: { code: 'RULE_EXECUTOR_STATE_CHANGED' } } })
    const w = mountSection()
    await flushPromises()
    const reads = getMock.mock.calls.length
    await btn(w).trigger('click')
    await flushPromises()
    expect(getMock.mock.calls.length).toBe(reads + 1)
  })

  it('下一步按鈕：取得公鑰開公鑰彈出框（讀取公鑰一次）；憑證庫在新分頁開啟；更換開更換對話框', async () => {
    exportMock.mockResolvedValue('ssh-ed25519 AAAA test')
    getCheckMock.mockResolvedValue(state({ success: false, code: 'RULE_EXECUTOR_CHECK_LOGIN_FAILED', method: '' }))
    let w = mountSection()
    await flushPromises()
    await w.get('[data-test="login-check-fix"]').trigger('click')
    await flushPromises()
    expect(exportMock).toHaveBeenCalledTimes(1)
    w.unmount()

    const open = vi.spyOn(window, 'open').mockImplementation(() => null)
    getCheckMock.mockResolvedValue(state({ success: false, code: 'RULE_EXECUTOR_CHECK_ROTATION_PENDING', method: '' }))
    w = mountSection()
    await flushPromises()
    await w.get('[data-test="login-check-fix"]').trigger('click')
    expect(open).toHaveBeenCalledWith('/credentials?credential=31', '_blank', 'noopener')
    open.mockRestore()
    w.unmount()

    getCheckMock.mockResolvedValue(state({ success: false, code: 'RULE_EXECUTOR_CHECK_UNAVAILABLE', method: '' }))
    w = mountSection()
    await flushPromises()
    await w.get('[data-test="login-check-fix"]').trigger('click')
    await flushPromises()
    expect(w.findComponent({ name: 'ExecutorSetupDialog' }).props('modelValue')).toBe(true)
  })

  it('主機金鑰不符：下一步把視線帶到主機金鑰區的按鈕', async () => {
    getCheckMock.mockResolvedValue(state({ success: false, code: 'RULE_EXECUTOR_CHECK_HOST_KEY_MISMATCH', method: '' }))
    const hk = document.createElement('div')
    hk.className = 'host-key-item'
    const hkBtn = document.createElement('button')
    hk.appendChild(hkBtn)
    document.body.appendChild(hk)
    const scroll = vi.fn()
    hk.scrollIntoView = scroll
    const w = mountSection()
    await flushPromises()
    await w.get('[data-test="login-check-fix"]').trigger('click')
    expect(scroll).toHaveBeenCalled()
    expect(document.activeElement).toBe(hkBtn)
    hk.remove()
  })
})

describe('ExecutorLoginCheck 停用條件與指紋提示', () => {
  it('RDP：按鈕停用、說明文字在、不發任何測試登入請求', async () => {
    getMock.mockResolvedValue(generated({ secret_type: 'password', source: 'inline', has_public_key: false }))
    const w = mountSection({ protocol: 'rdp' })
    await flushPromises()
    expect(btn(w).attributes('disabled')).toBeDefined()
    expect(w.get('[data-test="login-check-unsupported"]').text()).toBe('這類主機目前不支援測試登入')
    expect(getCheckMock).not.toHaveBeenCalled()
    await btn(w).trigger('click')
    expect(runCheckMock).not.toHaveBeenCalled()
  })

  it('Windows 族（windows_ssh）同樣停用', async () => {
    const w = mountSection({ windowsFamily: true })
    await flushPromises()
    expect(btn(w).attributes('disabled')).toBeDefined()
    expect(w.find('[data-test="login-check-unsupported"]').exists()).toBe(true)
  })

  it('沒有記錄過主機指紋：按鈕下一行提示；有記錄時沒有', async () => {
    let w = mountSection({ hostKeyRecorded: false })
    await flushPromises()
    expect(w.get('[data-test="login-check-hostkey-note"]').text()).toBe('這台還沒有記錄主機指紋，這次登入會記下目前的指紋。')
    w = mountSection({ hostKeyRecorded: true })
    await flushPromises()
    expect(w.find('[data-test="login-check-hostkey-note"]').exists()).toBe(false)
  })

  it('以角色預覽中：測試登入鈕停用並附說明（v-preview-write）', async () => {
    setPreviewOverlay({ roleId: 1, roleName: '預覽角色', permissions: new Set(['asset:view', 'asset:executor-manage']), entryStates: [], range: null })
    try {
      const w = mountSection()
      await flushPromises()
      expect(btn(w).attributes('aria-description')).toBeTruthy()
      await btn(w).trigger('click')
      expect(runCheckMock).not.toHaveBeenCalled()
    } finally {
      clearPreviewOverlay()
    }
  })
})

describe('ExecutorLoginCheck 落點與焦點', () => {
  it('落點表有 executor-test-login，捲到區塊並聚焦測試登入鈕；按鈕標了同名 data-focus', async () => {
    expect(EDIT_FOCUS_TARGETS['executor-test-login']).toEqual({
      scroll: '[data-focus="executor"]',
      focus: '[data-focus="executor-test-login"]',
    })
    const w = mountSection()
    await flushPromises()
    expect(btn(w).attributes('data-focus')).toBe('executor-test-login')
    expect(document.querySelectorAll('[data-focus="executor-test-login"]')).toHaveLength(1)
  })

  it('測試進行中焦點一直留在同一顆按鈕上（不經過 body），結果回來後仍在', async () => {
    const d = deferred()
    runCheckMock.mockReturnValue(d.promise)
    const w = mountSection()
    await flushPromises()
    const el = btn(w).element
    el.focus()
    await btn(w).trigger('click')
    await flushPromises()
    expect(document.activeElement).toBe(el)
    expect(document.activeElement).not.toBe(document.body)
    d.resolve({ success: true, code: '', method: 'executor_sudo_nopasswd', inventory_read: 'ok', checked_at: '2026-11-02T17:10:00', stale: false })
    await flushPromises()
    expect(document.activeElement).toBe(el)
  })

  it('按下按鈕後焦點若因停用而掉落，結果出來後回到同一顆按鈕', async () => {
    const d = deferred()
    runCheckMock.mockReturnValue(d.promise)
    const w = mountSection()
    await flushPromises()
    const el = btn(w).element
    el.focus()
    expect(document.activeElement).toBe(el)
    await btn(w).trigger('click')
    // 停用的按鈕在瀏覽器會失去焦點，這裡模擬
    el.blur()
    d.resolve({ success: true, code: '', method: 'executor_sudo_nopasswd', inventory_read: 'ok', checked_at: '2026-11-02T17:10:00', stale: false })
    await flushPromises()
    expect(document.activeElement).toBe(el)
  })

  it('焦點不在按鈕上時（使用者已去別處），結果回來不搶焦點', async () => {
    const d = deferred()
    runCheckMock.mockReturnValue(d.promise)
    const other = document.createElement('input')
    document.body.appendChild(other)
    const w = mountSection()
    await flushPromises()
    await btn(w).trigger('click')
    other.focus()
    d.resolve({ success: true, code: '', method: 'executor_sudo_nopasswd', inventory_read: 'ok', checked_at: '2026-11-02T17:10:00', stale: false })
    await flushPromises()
    expect(document.activeElement).toBe(other)
    other.remove()
  })

  it('狀態行是 role=status 的即時區域，結果更新會被朗讀', async () => {
    const w = mountSection()
    await flushPromises()
    const box = w.get('[data-test="login-check-box"]')
    expect(box.attributes('role')).toBe('status')
    expect(box.attributes('aria-live')).toBe('polite')
  })
})

describe('ExecutorLoginCheck 三語', () => {
  it('三語 loginCheck 鍵集相等，且 zh-TW 的結果碼文案鍵涵蓋九個碼', async () => {
    const en = (await import('@/i18n/locales/en-US.json')).default
    const ja = (await import('@/i18n/locales/ja-JP.json')).default
    const keys = (o, p = '') => Object.entries(o).flatMap(([k, v]) => (v && typeof v === 'object' ? keys(v, `${p}${k}.`) : [`${p}${k}`]))
    const zhKeys = keys(zhTW.assetExecutor.loginCheck).sort()
    expect(keys(en.assetExecutor.loginCheck).sort()).toEqual(zhKeys)
    expect(keys(ja.assetExecutor.loginCheck).sort()).toEqual(zhKeys)
    expect(Object.keys(zhTW.assetExecutor.loginCheck.result)).toHaveLength(10)
  })
})
