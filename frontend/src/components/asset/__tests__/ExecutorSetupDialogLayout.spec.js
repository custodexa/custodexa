import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import ExecutorSetupDialog from '@/components/asset/ExecutorSetupDialog.vue'
import CredentialPicker from '@/components/credential/CredentialPicker.vue'
import { setCapabilitiesForTests, resetCapabilities } from '@/composables/useCapabilities'
import zhTW from '@/i18n/locales/zh-TW.json'
import enUS from '@/i18n/locales/en-US.json'
import jaJP from '@/i18n/locales/ja-JP.json'

// 設定對話框的呈現細節：台數原地更新、結果頁、轉換畫面、共用憑證選項、版面與焦點。

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
const KEYCRED = (over = {}) => ({ id: 31, name: 'ops-exec-key', username: 'cx-exec', secret_type: 'ssh_key', binding_count: 7, purpose: 'executor', ...over })

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

async function toShared(w, id = 32) {
  await w.get('[data-test="source-card-shared"]').trigger('click')
  await flushPromises()
  w.getComponent(CredentialPicker).vm.$emit('update:modelValue', id)
  await flushPromises()
}

describe('ExecutorHostCountInPlace', () => {
  it('伺服器回 8 台：確認框標題、內文、勾選文字原地改為 8，勾選清空、送出鈕停用', async () => {
    const w = await mountDialog()
    await toShared(w)
    await w.get('[data-test="dlg-shared-check"] input').setValue(true)
    putMock.mockRejectedValueOnce(err409('RULE_EXECUTOR_SHARED_HOST_COUNT', { params: { count: 8 } }))
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="dlg-shared-title"]').text()).toContain('8 台')
    expect(w.get('[data-test="dlg-shared-title"]').text()).not.toContain('7 台')
    expect(w.get('[data-test="dlg-shared-body"]').text()).toContain('等於 8 台都外洩')
    expect(w.get('[data-test="dlg-shared-check"]').text()).toContain('8 台主機')
    expect(w.vm.ack).toBe(false)
    expect(w.get('[data-test="dlg-shared-check"] input').element.checked).toBe(false)
    expect(w.get('[data-test="dlg-submit"]').attributes('disabled')).toBeDefined()
    expect(w.get('[data-test="dlg-error-text"]').text()).toContain('台數從 7 台變成 8 台')
  })

  it('原地更新後自行勾選再按「設定」，以 8 台送出', async () => {
    const w = await mountDialog()
    await toShared(w)
    await w.get('[data-test="dlg-shared-check"] input').setValue(true)
    putMock.mockRejectedValueOnce(err409('RULE_EXECUTOR_SHARED_HOST_COUNT', { params: { count: 8 } }))
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    await w.get('[data-test="dlg-shared-check"] input').setValue(true)
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    expect(putMock).toHaveBeenLastCalledWith(5, expect.objectContaining({ acknowledged_host_count: 8 }))
  })
})

describe('ExecutorGenerateResult', () => {
  it('結果頁有金鑰指紋列與複製圖示、公鑰框、有樣式的複製／下載鈕、警示框與日誌句，焦點在結果開頭', async () => {
    putMock.mockResolvedValue({ configured: true, username: 'cx-exec', fingerprint: 'SHA256:7QmZ' })
    const w = await mountDialog()
    await w.get('input[data-test="dlg-username"]').setValue('cx-exec')
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="pk-fingerprint"]').text()).toBe('SHA256:7QmZ')
    const copyFp = w.get('[data-test="pk-copy-fingerprint"]')
    expect(copyFp.find('svg').exists()).toBe(true)
    expect(copyFp.attributes('aria-label')).toBe(zhTW.assetExecutor.copyFingerprint)
    for (const k of ['pk-copy', 'pk-download']) {
      const b = w.get(`[data-test="${k}"]`)
      expect(b.classes()).toContain('el-button')
      expect(b.find('svg').exists()).toBe(true)
    }
    expect(w.get('[data-test="pk-line"]').element.closest('.pk-box')).not.toBeNull()
    const next = w.get('[data-test="dlg-result-next"]')
    expect(next.classes()).toContain('is-warning')
    expect(next.get('[data-test="notice-box-title"]').text()).toContain('還差一步')
    expect(next.text()).toContain('還差一步：把這行公鑰加到這台主機上 cx-exec 的登入金鑰清單。')
    expect(next.text()).toContain('加好之後按「完成」')
    expect(w.get('[data-test="dlg-result-logged"]').text()).toBe(zhTW.assetExecutor.publicKey.loggedEvery)
    expect(document.activeElement).toBe(w.get('[data-test="dlg-result-head"]').element)
  })
})

describe('ExecutorConvertLayout', () => {
  async function toConvert() {
    const w = await mountDialog()
    await w.get('[data-test="source-convert-link"]').trigger('click')
    await flushPromises()
    return w
  }

  it('標題換為「轉換既有帳號」；欄名「要轉換的帳號」必填、佔位「選擇這台的帳號」', async () => {
    const w = await toConvert()
    expect(w.get('[data-test="dlg-title"]').text()).toBe('轉換既有帳號')
    const item = w.get('[data-test="dlg-convert-select"]').element.closest('.el-form-item')
    expect(item.classList.contains('is-required')).toBe(true)
    expect(item.textContent).toContain('要轉換的帳號')
    expect(w.html()).toContain('選擇這台的帳號')
    await w.get('[data-test="dlg-back"]').trigger('click')
    expect(w.get('[data-test="dlg-title"]').text()).toBe('設定堡壘機專用帳號')
  })

  it('可轉換列寫「專用 · 型別」，停用列名稱與原因分開', async () => {
    const w = await toConvert()
    const step = w.getComponent({ name: 'ExecutorConvertStep' })
    expect(step.vm.$.setupState.optionMeta({ has_password: true })).toBe('專用 · 密碼')
    expect(step.vm.$.setupState.optionMeta({ has_private_key: true })).toBe('專用 · SSH 金鑰')
    expect(step.vm.$.setupState.disabledReason({ is_default: true })).toContain('預設帳號不能轉換')
    expect(step.vm.$.setupState.disabledReason({ shared_credential: true })).toContain('共用憑證的帳號不能轉換')
    expect(step.vm.$.setupState.disabledReason({})).toBe('')
  })

  it('伺服器擋下時錯誤在帳號選單正下方、三件事之前；修正鈕主要、重新檢查次要', async () => {
    const w = await toConvert()
    w.vm.convertAccountId = 2
    await flushPromises()
    putMock.mockRejectedValueOnce(err409('RULE_EXECUTOR_CONVERT_CANDIDATE_PENDING'))
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    const select = w.get('[data-test="dlg-convert-select"]').element
    const error = w.get('[data-test="dlg-error"]').element
    const effects = w.get('[data-test="dlg-convert-effects"]').element
    expect(select.compareDocumentPosition(error) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(error.compareDocumentPosition(effects) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(w.get('[data-test="dlg-fix"]').classes()).toContain('el-button--primary')
    expect(w.get('[data-test="dlg-recheck"]').classes()).not.toContain('el-button--primary')
    expect(w.get('[data-test="dlg-submit"]').classes()).not.toContain('el-button--primary')
  })
})

describe('ExecutorSharedOptions', () => {
  it('選項後綴：專用帳號列寫「帳號 · 型別 · 台數」，Windows 金鑰列寫「型別 · 原因」，人員連線列只寫原因', async () => {
    const w = await mountDialog({ windowsFamily: true })
    await w.get('[data-test="source-card-shared"]').trigger('click')
    await flushPromises()
    const picker = w.getComponent(CredentialPicker)
    expect(picker.vm.optionMeta(PWDCRED({ binding_count: 3 }))).toBe('帳號 cx-exec · 密碼 · 已是 3 台的專用帳號')
    expect(picker.vm.optionMeta(KEYCRED())).toBe('SSH 金鑰 · Windows 主機只能用密碼')
    expect(picker.vm.optionMeta(PWDCRED({ purpose: 'login', username: 'app' }))).toBe('已是人員連線用的帳號')
    expect(picker.vm.optionMeta(PWDCRED({ purpose: undefined, username: 'svc' }))).toBe('帳號 svc · 密碼')
  })

  it('選定值也帶「帳號 · 型別」', async () => {
    const w = await mountDialog()
    await toShared(w)
    expect(w.getComponent(CredentialPicker).vm.selectedMeta(32)).toBe('帳號 cx-exec · 密碼')
    expect(w.find('[data-test="picker-selected-meta"]').text()).toBe('帳號 cx-exec · 密碼')
  })
})

describe('ExecutorPurposeMismatch', () => {
  it('錯誤句含後半句、修正鈕改用平台產生金鑰；不再顯示台數確認框', async () => {
    const w = await mountDialog()
    await toShared(w)
    await w.get('[data-test="dlg-shared-check"] input').setValue(true)
    putMock.mockRejectedValueOnce(err409('RULE_CREDENTIAL_PURPOSE_MISMATCH'))
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="dlg-error-text"]').text()).toContain('請選另一組，或改用平台產生金鑰。')
    expect(w.find('[data-test="dlg-shared-confirm"]').exists()).toBe(false)
    expect(w.find('[data-test="dlg-credential-username"]').exists()).toBe(false)
  })

  it('Windows 族的後半句改為直接輸入密碼', async () => {
    const w = await mountDialog({ windowsFamily: true })
    await toShared(w)
    await w.get('[data-test="dlg-shared-check"] input').setValue(true)
    putMock.mockRejectedValueOnce(err409('RULE_CREDENTIAL_PURPOSE_MISMATCH'))
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="dlg-error-text"]').text()).toContain('請選另一組，或改用直接輸入密碼。')
    expect(w.get('[data-test="dlg-fix"]').text()).toBe('改用直接輸入密碼')
  })
})

describe('ExecutorDialogLayout', () => {
  it('用途句在資訊框內；有「秘密從哪裡來」標籤；建議標與卡片標題同列', async () => {
    const w = await mountDialog()
    expect(w.get('[data-test="dlg-purpose"]').classes()).toContain('info-box')
    expect(w.get('[data-test="dlg-source-label"]').text()).toBe('秘密從哪裡來')
    const head = w.get('[data-test="source-card-generate"] .card-head')
    expect(head.text()).toContain('平台產生金鑰')
    expect(head.text()).toContain('建議')
  })

  it('帳號名稱必填；「怎麼準備這個帳號」接在提示句之後', async () => {
    const w = await mountDialog()
    const item = w.get('input[data-test="dlg-username"]').element.closest('.el-form-item')
    expect(item.classList.contains('is-required')).toBe(true)
    const hint = w.get('[data-test="dlg-username-hint"]')
    expect(hint.text()).toContain('這台主機上要有這個帳號')
    expect(hint.find('[data-test="dlg-prepare-link"]').text()).toBe('怎麼準備這個帳號')
  })

  it('「這台已有合適的帳號？轉換既有帳號」在底部左側，與取消／送出同一列', async () => {
    const w = await mountDialog()
    const left = w.get('.stub-footer .footer-left')
    expect(left.text()).toContain('這台已有合適的帳號？')
    expect(left.find('[data-test="source-convert-link"]').exists()).toBe(true)
    expect(w.find('.stub-body [data-test="source-convert-link"]').exists()).toBe(false)
    expect(w.get('.stub-footer .footer-right').find('[data-test="dlg-submit"]').exists()).toBe(true)
  })

  it('Windows 族卡片順序：直接輸入密碼在前、共用憑證在後', async () => {
    const w = await mountDialog({ windowsFamily: true })
    const keys = w.findAll('.source-card').map((c) => c.attributes('data-test'))
    expect(keys).toEqual(['source-card-inline', 'source-card-shared'])
    const ssh = await mountDialog()
    expect(ssh.findAll('.source-card').map((c) => c.attributes('data-test'))).toEqual(['source-card-generate', 'source-card-shared', 'source-card-inline'])
  })
})

describe('ExecutorDialogLocale', () => {
  const keys = ['dialog.sourceLabel', 'dialog.prepareLink', 'dialog.optionAccount', 'dialog.resultNextTitle', 'dialog.resultNextBody',
    'convert.placeholder', 'convert.accountLabel', 'error.purposeMismatchWindows', 'publicKey.label', 'publicKey.addHint', 'credentialLead']
  const get = (loc, k) => k.split('.').reduce((o, p) => o?.[p], loc.assetExecutor)
  it('新增與改動的鍵三語都有值且無圈號', () => {
    for (const loc of [zhTW, enUS, jaJP]) {
      for (const k of keys) {
        expect(typeof get(loc, k)).toBe('string')
        expect(get(loc, k)).not.toMatch(/[①-⑳]/)
      }
      expect(loc.assetExecutor.dialog.resultNext).toBeUndefined()
    }
    expect(zhTW.assetExecutor.convert.accountLabel).toBe('要轉換的帳號')
    expect(zhTW.assetExecutor.error.purposeMismatch).toMatch(/請選另一組，或改用平台產生金鑰。$/)
  })
})
