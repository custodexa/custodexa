import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import ElementPlus from 'element-plus'
import ExecutorSetupDialog from '@/components/asset/ExecutorSetupDialog.vue'
import CredentialPicker from '@/components/credential/CredentialPicker.vue'
import { setCapabilitiesForTests, resetCapabilities } from '@/composables/useCapabilities'

// 設定對話框的呈現（二）：錯誤框、焦點、轉換選單排序、警示框、結果頁、提示句。

enableAutoUnmount(afterEach)

class ObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() { return [] }
}
vi.stubGlobal('MutationObserver', ObserverStub)
vi.stubGlobal('ResizeObserver', ObserverStub)

const putMock = vi.fn()
const exportMock = vi.fn()
vi.mock('@/api/assetExecutor', () => ({
  putAssetExecutor: (...a) => putMock(...a),
  exportAssetExecutorPublicKey: (...a) => exportMock(...a),
}))
const listAccountsMock = vi.fn()
vi.mock('@/api/assetAccounts', () => ({ listAssetAccounts: (...a) => listAccountsMock(...a) }))
const listCredsMock = vi.fn()
vi.mock('@/api/credentials', () => ({ listCredentials: (...a) => listCredsMock(...a) }))

const dialogStub = {
  props: ['modelValue', 'title'],
  template: '<div v-if="modelValue" class="dialog-stub"><h2 data-test="dlg-title">{{ title }}</h2><div class="stub-body"><slot /></div><div class="stub-footer"><slot name="footer" /></div></div>',
}

const ALL = ['asset:executor-manage', 'credential:create', 'credential:bind', 'credential:update']
const PWDCRED = (over = {}) => ({ id: 32, name: 'exec-pass', username: 'cx-exec', secret_type: 'password', binding_count: 6, purpose: 'executor', ...over })

async function mountDialog(props = {}) {
  const wrapper = mount(ExecutorSetupDialog, {
    global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub } },
    props: { modelValue: false, mode: 'set', assetId: 5, assetName: 'web-01', windowsFamily: false, expectedAccountId: 0, current: {}, ...props },
    attachTo: document.body,
  })
  await wrapper.setProps({ modelValue: true })
  await flushPromises()
  return wrapper
}
const err409 = (code, extra = {}) => ({ response: { status: 409, data: { code, ...extra } } })

beforeEach(() => {
  vi.clearAllMocks()
  setCapabilitiesForTests(ALL)
  putMock.mockResolvedValue({})
  exportMock.mockResolvedValue('ssh-ed25519 AAAA cx-exec')
  listAccountsMock.mockResolvedValue({ data: [
    { id: 1, username: 'root', is_default: true, shared_credential: false, has_password: true },
    { id: 2, username: 'ops', is_default: false, shared_credential: false, has_password: true, credential_id: 12 },
    { id: 4, username: 'deploy', is_default: false, shared_credential: false, has_private_key: true },
    { id: 3, username: 'app', is_default: false, shared_credential: true },
  ] })
  listCredsMock.mockResolvedValue({ data: [PWDCRED()] })
})
afterEach(() => resetCapabilities())

async function fillInline(w, name) {
  await w.get('[data-test="source-card-inline"]').trigger('click')
  await w.get('input[data-test="dlg-username"]').setValue(name)
  await w.get('input[data-test="dlg-password"]').setValue('pw-123456')
}
async function toConvertWith(w, accountId) {
  await w.get('[data-test="source-convert-link"]').trigger('click')
  await flushPromises()
  w.vm.convertAccountId = accountId
  await flushPromises()
}
const formItemOf = (w, sel) => w.get(sel).element.closest('.el-form-item')

describe('ExecutorErrorBox', () => {
  it('帳號名稱重複：紅色錯誤框（叉號圖示、粗體首句、說明句、框內主要修正鈕），帳號名稱欄紅框，底部不再有轉換入口', async () => {
    putMock.mockRejectedValue(err409('CONFLICT_ACCOUNT_USERNAME'))
    const w = await mountDialog()
    await fillInline(w, 'ops')
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    const box = w.get('[data-test="dlg-error"]')
    expect(box.classes()).toEqual(expect.arrayContaining(['notice-box', 'is-danger']))
    expect(box.find('[data-test="notice-box-icon"]').exists()).toBe(true)
    expect(box.get('[data-test="dlg-error-head"]').element.tagName).toBe('STRONG')
    expect(box.get('[data-test="dlg-error-head"]').text()).toBe('尚未設定：這台已有名為 ops 的帳號。')
    expect(box.get('[data-test="dlg-error-text"]').text()).toContain('不必重新輸入密碼')
    expect(box.find('[data-test="dlg-fix"]').classes()).toContain('el-button--primary')
    expect(formItemOf(w, 'input[data-test="dlg-username"]').classList.contains('is-error')).toBe(true)
    expect(w.find('[data-test="source-convert-link"]').exists()).toBe(false)
    await w.get('input[data-test="dlg-username"]').setValue('ops2')
    expect(formItemOf(w, 'input[data-test="dlg-username"]').classList.contains('is-error')).toBe(false)
    expect(w.find('[data-test="source-convert-link"]').exists()).toBe(true)
  })

  it('共用主機數待確認：錯誤框在黃色確認框之外、其正下方', async () => {
    const w = await mountDialog()
    await w.get('[data-test="source-card-shared"]').trigger('click')
    await flushPromises()
    w.getComponent(CredentialPicker).vm.$emit('update:modelValue', 32)
    await flushPromises()
    await w.get('[data-test="dlg-shared-check"] input').setValue(true)
    putMock.mockRejectedValueOnce(err409('RULE_EXECUTOR_SHARED_HOST_COUNT', { params: { count: 8 } }))
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    const confirm = w.get('[data-test="dlg-shared-confirm"]').element
    const error = w.get('[data-test="dlg-error"]').element
    expect(confirm.contains(error)).toBe(false)
    expect(confirm.compareDocumentPosition(error) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(w.get('[data-test="dlg-error-head"]').text()).toBe('尚未設定：這組密碼現在用在 8 台。')
  })

  it('憑證用途不符：共用憑證欄紅框', async () => {
    const w = await mountDialog()
    await w.get('[data-test="source-card-shared"]').trigger('click')
    await flushPromises()
    w.getComponent(CredentialPicker).vm.$emit('update:modelValue', 32)
    await flushPromises()
    await w.get('[data-test="dlg-shared-check"] input').setValue(true)
    putMock.mockRejectedValueOnce(err409('RULE_CREDENTIAL_PURPOSE_MISMATCH'))
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    expect(w.getComponent(CredentialPicker).element.closest('.el-form-item').classList.contains('is-error')).toBe(true)
  })

  it('轉換對象待處理：要轉換的帳號欄紅框；在新分頁開啟的修正鈕帶外部連結圖示，重新檢查鈕帶圖示', async () => {
    const w = await mountDialog()
    await toConvertWith(w, 2)
    putMock.mockRejectedValueOnce(err409('RULE_EXECUTOR_CONVERT_CANDIDATE_PENDING'))
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    expect(formItemOf(w, '[data-test="dlg-convert-select"]').classList.contains('is-error')).toBe(true)
    expect(w.get('[data-test="dlg-fix"]').find('[data-test="dlg-fix-external"]').exists()).toBe(true)
    expect(w.get('[data-test="dlg-recheck"]').find('svg').exists()).toBe(true)
  })

  it('帳號名稱重複時的修正鈕不在新分頁開啟，不帶外部連結圖示', async () => {
    putMock.mockRejectedValue(err409('CONFLICT_ACCOUNT_USERNAME'))
    const w = await mountDialog()
    await fillInline(w, 'ops')
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="dlg-fix-external"]').exists()).toBe(false)
  })
})

describe('ExecutorErrorFocus', () => {
  it('帳號名稱重複：送出被擋後焦點在錯誤框內的修正鈕', async () => {
    putMock.mockRejectedValue(err409('CONFLICT_ACCOUNT_USERNAME'))
    const w = await mountDialog()
    await fillInline(w, 'ops')
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    expect(document.activeElement).toBe(w.get('[data-test="dlg-fix"]').element)
    expect(document.activeElement).not.toBe(document.body)
  })

  it('共用主機數待確認：焦點在「確認 8 台並設定」', async () => {
    const w = await mountDialog()
    await w.get('[data-test="source-card-shared"]').trigger('click')
    await flushPromises()
    w.getComponent(CredentialPicker).vm.$emit('update:modelValue', 32)
    await flushPromises()
    await w.get('[data-test="dlg-shared-check"] input').setValue(true)
    putMock.mockRejectedValueOnce(err409('RULE_EXECUTOR_SHARED_HOST_COUNT', { params: { count: 8 } }))
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    expect(document.activeElement).toBe(w.get('[data-test="dlg-fix"]').element)
    expect(document.activeElement.textContent).toContain('確認 8 台並設定')
  })

  it('轉換時遇到改密中：焦點在框內的主要修正鈕；按重新檢查又被擋時焦點仍回到修正鈕', async () => {
    const w = await mountDialog()
    await toConvertWith(w, 2)
    putMock.mockRejectedValue(err409('RULE_CREDENTIAL_ROTATION_ACTIVE'))
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    expect(document.activeElement).toBe(w.get('[data-test="dlg-fix"]').element)
    await w.get('[data-test="dlg-recheck"]').trigger('click')
    await flushPromises()
    expect(document.activeElement).toBe(w.get('[data-test="dlg-fix"]').element)
  })

  it('沒有修正鈕的錯誤：焦點落在錯誤框本身', async () => {
    putMock.mockRejectedValue({ response: { status: 500, data: { code: 'INTERNAL_ASSET_EXECUTOR_WRITE' } } })
    const w = await mountDialog()
    await w.get('input[data-test="dlg-username"]').setValue('cx-exec')
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    const box = w.get('.dlg-error').element
    expect(box.getAttribute('tabindex')).toBe('-1')
    expect(document.activeElement).toBe(box)
  })
})

describe('ExecutorConvertMenu', () => {
  it('可轉換的排前、不能轉換的排後，同組維持帳號表順序', async () => {
    const w = await mountDialog()
    await w.get('[data-test="source-convert-link"]').trigger('click')
    await flushPromises()
    const step = w.getComponent({ name: 'ExecutorConvertStep' })
    expect(step.vm.$.setupState.sortedAccounts.map((a) => a.username)).toEqual(['ops', 'deploy', 'root', 'app'])
  })

  it('預設帳號列帶 ★，其他列沒有', async () => {
    const w = await mountDialog()
    await w.get('[data-test="source-convert-link"]').trigger('click')
    await flushPromises()
    await w.get('[data-test="dlg-convert-select"]').trigger('click')
    await flushPromises()
    expect(document.querySelector('[data-test="dlg-convert-star-1"]')).not.toBeNull()
    for (const id of [2, 3, 4]) expect(document.querySelector(`[data-test="dlg-convert-star-${id}"]`)).toBeNull()
  })

  it('三件事在黃色警示框內（圖示＋粗體標題），建議改密句在框外', async () => {
    const w = await mountDialog()
    await toConvertWith(w, 2)
    const box = w.get('[data-test="dlg-convert-effects"]')
    expect(box.classes()).toEqual(expect.arrayContaining(['notice-box', 'is-warning']))
    expect(box.find('[data-test="notice-box-icon"]').exists()).toBe(true)
    expect(box.get('[data-test="notice-box-title"]').text()).toBe('轉換後，ops 只給平台使用：')
    expect(box.findAll('li')).toHaveLength(3)
    const advice = w.get('[data-test="dlg-convert-advice"]').element
    expect(box.element.contains(advice)).toBe(false)
    expect(advice.textContent).toContain('建議到憑證庫改一次密碼')
  })
})

describe('ExecutorResultAndHints', () => {
  it('產生成功即 emit applied（背後區塊立刻更新），按「完成」才 emit done', async () => {
    putMock.mockResolvedValue({ configured: true, username: 'cx-exec', fingerprint: 'SHA256:7QmZ' })
    const w = await mountDialog()
    await w.get('input[data-test="dlg-username"]').setValue('cx-exec')
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    expect(w.emitted('applied')).toHaveLength(1)
    expect(w.emitted('done')).toBeUndefined()
    await w.get('[data-test="dlg-done"]').trigger('click')
    expect(w.emitted('done')).toHaveLength(1)
  })

  it('結果頁的還差一步為小號粗體標題的警示框，不是大圖示的 el-alert', async () => {
    putMock.mockResolvedValue({ configured: true, username: 'cx-exec', fingerprint: 'SHA256:7QmZ' })
    const w = await mountDialog()
    await w.get('input[data-test="dlg-username"]').setValue('cx-exec')
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    const next = w.get('[data-test="dlg-result-next"]')
    expect(next.classes()).toContain('notice-box')
    expect(next.find('.el-alert').exists()).toBe(false)
    expect(next.get('[data-test="notice-box-title"]').element.tagName).toBe('STRONG')
    expect(next.text()).toContain('加好之後按「完成」')
  })

  it('Windows 族帳號名稱下沒有提示句；非 Windows 仍有', async () => {
    const win = await mountDialog({ windowsFamily: true })
    expect(win.find('input[data-test="dlg-username"]').exists()).toBe(true)
    expect(win.find('[data-test="dlg-username-hint"]').exists()).toBe(false)
    const ssh = await mountDialog()
    expect(ssh.find('[data-test="dlg-username-hint"]').exists()).toBe(true)
  })

  it('共用確認框有警示圖示，建議句另起一行', async () => {
    const w = await mountDialog()
    await w.get('[data-test="source-card-shared"]').trigger('click')
    await flushPromises()
    w.getComponent(CredentialPicker).vm.$emit('update:modelValue', 32)
    await flushPromises()
    const box = w.get('[data-test="dlg-shared-confirm"]')
    expect(box.classes()).toContain('is-warning')
    expect(box.find('[data-test="notice-box-icon"]').exists()).toBe(true)
    const body = box.get('[data-test="dlg-shared-body"]')
    const advice = box.get('[data-test="dlg-shared-advice"]')
    expect(advice.text()).toBe('要共用時，建議改用平台產生的金鑰。')
    expect(body.text()).not.toContain('要共用時')
    expect(body.element.compareDocumentPosition(advice.element) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })
})

describe('ExecutorResultDetailsAndClose', () => {
  it('共用確認框的建議句為次要灰字（muted），內文不是', async () => {
    const w = await mountDialog()
    await w.get('[data-test="source-card-shared"]').trigger('click')
    await flushPromises()
    w.getComponent(CredentialPicker).vm.$emit('update:modelValue', 32)
    await flushPromises()
    expect(w.get('[data-test="dlg-shared-advice"]').classes()).toContain('muted')
    expect(w.get('[data-test="dlg-shared-body"]').classes()).not.toContain('muted')
  })

  it('結果頁的技術細節是藍色文字連結式展開，不是整列收合區塊；預設收合，按一下展開', async () => {
    putMock.mockResolvedValue({ configured: true, username: 'cx-exec', fingerprint: 'SHA256:7QmZ' })
    const w = await mountDialog()
    await w.get('input[data-test="dlg-username"]').setValue('cx-exec')
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    expect(w.find('.el-collapse').exists()).toBe(false)
    const toggle = w.get('[data-test="dlg-tech-toggle"]')
    expect(toggle.classes()).toEqual(expect.arrayContaining(['el-button--primary', 'is-link']))
    expect(toggle.text()).toBe('技術細節')
    expect(toggle.find('svg').exists()).toBe(true)
    expect(toggle.attributes('aria-expanded')).toBe('false')
    expect(w.find('[data-test="dlg-tech-body"]').exists()).toBe(false)
    await toggle.trigger('click')
    expect(toggle.attributes('aria-expanded')).toBe('true')
    expect(w.get('[data-test="dlg-tech-body"]').find('[data-test="executor-help-body"]').exists()).toBe(true)
    // 技術細節在還差一步框之後、日誌句之前
    const next = w.get('[data-test="dlg-result-next"]').element
    const logged = w.get('[data-test="dlg-result-logged"]').element
    expect(next.compareDocumentPosition(toggle.element) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(toggle.element.compareDocumentPosition(logged) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })

  it('送出中右上 × 仍畫出但停用，點了不關', async () => {
    const closeStub = {
      props: ['modelValue', 'showClose', 'beforeClose', 'closeOnPressEscape'],
      emits: ['update:modelValue'],
      template: '<div v-if="modelValue" class="dialog-stub"><button v-if="showClose !== false" data-test="stub-x" @click="beforeClose ? beforeClose(() => $emit(\'update:modelValue\', false)) : $emit(\'update:modelValue\', false)">x</button><slot /><slot name="footer" /></div>',
    }
    let release
    putMock.mockReturnValue(new Promise((r) => { release = r }))
    const w = mount(ExecutorSetupDialog, {
      global: { plugins: [ElementPlus], stubs: { 'el-dialog': closeStub } },
      props: { modelValue: false, mode: 'set', assetId: 5, assetName: 'web-01', windowsFamily: false, expectedAccountId: 0, current: {} },
      attachTo: document.body,
    })
    await w.setProps({ modelValue: true })
    await flushPromises()
    expect(w.get('.dialog-stub').classes()).toContain('executor-setup-dialog')
    expect(w.get('.dialog-stub').classes()).not.toContain('is-submitting')
    await w.get('input[data-test="dlg-username"]').setValue('cx-new')
    await w.get('[data-test="dlg-submit"]').trigger('click')
    expect(w.get('.dialog-stub').classes()).toContain('is-submitting')
    expect(w.find('[data-test="stub-x"]').exists()).toBe(true)
    await w.get('[data-test="stub-x"]').trigger('click')
    expect(w.emitted('update:modelValue')).toBeUndefined()
    release({ configured: true, username: 'cx-new' })
    await flushPromises()
    expect(w.get('.dialog-stub').classes()).not.toContain('is-submitting')
  })

  it('送出中 × 的停用樣式寫在非 scoped 規則（對話框傳送到 body）', () => {
    const sfc = readFileSync(join(process.cwd(), 'src/components/asset/ExecutorSetupDialog.vue'), 'utf8')
    const global = /<style>\s*([\s\S]*?)<\/style>/.exec(sfc)?.[1] || ''
    const rule = /\.executor-setup-dialog\.is-submitting \.el-dialog__headerbtn \{[^}]*\}/.exec(global)?.[0] || ''
    expect(rule).toMatch(/pointer-events: none/)
    expect(rule).toMatch(/opacity: 0\.5/)
    expect(sfc).not.toMatch(/:show-close=/)
  })
})
