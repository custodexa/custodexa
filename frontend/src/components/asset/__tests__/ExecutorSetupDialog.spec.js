import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import ExecutorSetupDialog from '@/components/asset/ExecutorSetupDialog.vue'
import CredentialPicker from '@/components/credential/CredentialPicker.vue'
import { setCapabilitiesForTests, resetCapabilities } from '@/composables/useCapabilities'

// 設定與更換堡壘機專用帳號的對話框。所有錯誤就地顯示，不呼叫全域訊息。

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
  template: '<div v-if="modelValue" class="dialog-stub"><h2 data-test="dlg-title">{{ title }}</h2><slot /><slot name="footer" /></div>',
}

const ALL = ['asset:executor-manage', 'credential:create', 'credential:bind', 'credential:update']
const KEYCRED = (over = {}) => ({ id: 31, name: 'fleet', username: 'cx-exec', secret_type: 'ssh_key', binding_count: 6, purpose: 'executor', ...over })
const PWDCRED = (over = {}) => ({ id: 32, name: 'fleet-pw', username: 'cx-exec', secret_type: 'password', binding_count: 6, purpose: 'executor', ...over })

async function mountDialog(props = {}) {
  const wrapper = mount(ExecutorSetupDialog, {
    global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub } },
    props: { modelValue: false, mode: 'set', assetId: 5, assetName: 'web-01', windowsFamily: false, expectedAccountId: 0, current: {}, ...props },
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
    { id: 1, username: 'root', is_default: true, shared_credential: false, credential_id: 11 },
    { id: 2, username: 'ops', is_default: false, shared_credential: false, credential_id: 12 },
    { id: 3, username: 'shared-u', is_default: false, shared_credential: true, credential_id: 13 },
  ] })
  listCredsMock.mockResolvedValue({ data: [KEYCRED(), PWDCRED()] })
})
afterEach(() => resetCapabilities())

describe('ExecutorSetupDialogSources', () => {
  it('SSH 預設平台產生且有建議標', async () => {
    const w = await mountDialog()
    expect(w.get('[data-test="source-card-generate"]').classes()).toContain('active')
    expect(w.get('[data-test="source-card-generate"]').text()).toContain('建議')
  })

  it('RDP 無產生卡、預設直接輸入密碼、有原因句', async () => {
    const w = await mountDialog({ windowsFamily: true })
    expect(w.find('[data-test="source-card-generate"]').exists()).toBe(false)
    expect(w.get('[data-test="source-card-inline"]').classes()).toContain('active')
    expect(w.get('[data-test="dlg-windows-note"]').text()).toContain('Windows 主機只能用密碼')
    expect(w.find('[data-test="dlg-secret-type"]').exists()).toBe(false)
  })

  it('只持 credential:manage 時三卡與轉換入口全停用並各有原因', async () => {
    setCapabilitiesForTests(['asset:executor-manage', 'credential:manage'])
    const w = await mountDialog()
    for (const k of ['generate', 'shared', 'inline']) {
      expect(w.get(`[data-test="source-card-${k}"]`).attributes('disabled')).toBeDefined()
      expect(w.find(`[data-test="source-reason-${k}"]`).exists()).toBe(true)
    }
    expect(w.get('[data-test="source-convert-link"]').attributes('disabled')).toBeDefined()
    expect(w.find('[data-test="dlg-no-permission"]').exists()).toBe(true)
  })

  it('只缺 credential:create 時兩卡停用、共用可用', async () => {
    setCapabilitiesForTests(['asset:executor-manage', 'credential:bind', 'credential:update'])
    const w = await mountDialog()
    expect(w.get('[data-test="source-card-generate"]').attributes('disabled')).toBeDefined()
    expect(w.get('[data-test="source-card-inline"]').attributes('disabled')).toBeDefined()
    expect(w.get('[data-test="source-card-shared"]').attributes('disabled')).toBeUndefined()
  })

  it('更換模式標題與說明含目前帳號名；送出帶 expected_account_id', async () => {
    const w = await mountDialog({
      mode: 'replace', expectedAccountId: 7,
      current: { username: 'cx-exec', source: 'generate', has_public_key: true, credential: {} },
    })
    expect(w.get('[data-test="dlg-title"]').text()).toBe('更換堡壘機專用帳號')
    expect(w.text()).toContain('目前是 cx-exec（平台產生的金鑰）')
    await w.get('input[data-test="dlg-username"]').setValue('cx-new')
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    expect(putMock).toHaveBeenCalledWith(5, { source: 'generate', username: 'cx-new', expected_account_id: 7 })
  })

  it('送出中不可關閉', async () => {
    let release
    putMock.mockReturnValue(new Promise((r) => { release = r }))
    const w = await mountDialog()
    await w.get('input[data-test="dlg-username"]').setValue('cx-new')
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await w.get('[data-test="dlg-cancel"]').trigger('click')
    expect(w.emitted('update:modelValue')).toBeUndefined()
    release({})
    await flushPromises()
  })
})

describe('ExecutorGenerate', () => {
  it('成功後對話框內有公鑰、匯出 1 次、還差一步句；完成後 emit done', async () => {
    const w = await mountDialog()
    await w.get('input[data-test="dlg-username"]').setValue('cx-exec')
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    expect(exportMock).toHaveBeenCalledTimes(1)
    expect(w.get('[data-test="dlg-result-next"]').text()).toContain('還差一步')
    expect(w.get('[data-test="pk-line"]').text()).toContain('ssh-ed25519')
    await w.get('[data-test="dlg-done"]').trigger('click')
    expect(w.emitted('done')[0][0]).toEqual({ kind: 'set' })
  })
})

describe('ExecutorInline', () => {
  async function fillInline(name) {
    const w = await mountDialog()
    await w.get('[data-test="source-card-inline"]').trigger('click')
    await w.get('input[data-test="dlg-username"]').setValue(name)
    await w.get('input[data-test="dlg-password"]').setValue('topsecret-123')
    return w
  }

  it('同名衝突：錯誤在帳號名稱欄下方、修正鈕非送出鈕、按修正後切到轉換並預選同名帳號', async () => {
    putMock.mockRejectedValue(err409('CONFLICT_ACCOUNT_USERNAME'))
    const w = await fillInline('ops')
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    const e = w.get('[data-test="dlg-error"]')
    expect(e.attributes('data-placement')).toBe('field-username')
    expect(e.text()).toContain('這台已有名為 ops 的帳號')
    expect(w.get('[data-test="dlg-submit"]').classes()).not.toContain('el-button--primary')
    await w.get('[data-test="dlg-fix"]').trigger('click')
    await flushPromises()
    expect(w.vm.step).toBe('convert')
    expect(w.vm.convertAccountId).toBe(2)
  })

  it('同名者為預設帳號時只切換不預選', async () => {
    putMock.mockRejectedValue(err409('CONFLICT_ACCOUNT_USERNAME'))
    const w = await fillInline('root')
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    await w.get('[data-test="dlg-fix"]').trigger('click')
    await flushPromises()
    expect(w.vm.step).toBe('convert')
    expect(w.vm.convertAccountId).toBeNull()
  })

  it('改帳號名稱後錯誤收起；切換來源後密碼欄為空；console 不含秘密', async () => {
    const spies = ['log', 'error', 'warn', 'info'].map((k) => vi.spyOn(console, k).mockImplementation(() => {}))
    putMock.mockRejectedValue(err409('CONFLICT_ACCOUNT_USERNAME'))
    const w = await fillInline('ops')
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    await w.get('input[data-test="dlg-username"]').setValue('ops2')
    expect(w.find('[data-test="dlg-error"]').exists()).toBe(false)
    await w.get('[data-test="source-card-shared"]').trigger('click')
    await w.get('[data-test="source-card-inline"]').trigger('click')
    expect(w.get('input[data-test="dlg-password"]').element.value).toBe('')
    for (const s of spies) expect(JSON.stringify(s.mock.calls)).not.toContain('topsecret-123')
    spies.forEach((s) => s.mockRestore())
  })

  it('RDP 只有密碼', async () => {
    const w = await mountDialog({ windowsFamily: true })
    expect(w.find('[data-test="dlg-secret-type"]').exists()).toBe(false)
    expect(w.find('[data-test="dlg-password"]').exists()).toBe(true)
    expect(w.find('[data-test="dlg-private-key"]').exists()).toBe(false)
  })
})

describe('ExecutorShared', () => {
  async function toShared(props = {}, credential = PWDCRED()) {
    listCredsMock.mockResolvedValue({ data: [credential] })
    const w = await mountDialog(props)
    await w.get('[data-test="source-card-shared"]').trigger('click')
    await flushPromises()
    w.getComponent(CredentialPicker).vm.$emit('update:modelValue', credential.id)
    await flushPromises()
    return w
  }

  it('binding_count=6 預填 7；更換且同一憑證預填 6；未勾選時設定鈕停用', async () => {
    const w = await toShared()
    expect(w.get('[data-test="dlg-shared-title"]').text()).toContain('7 台')
    expect(w.get('[data-test="dlg-submit"]').attributes('disabled')).toBeDefined()
    const r = await toShared({ mode: 'replace', current: { credential: { credential_id: 32 } } })
    expect(r.get('[data-test="dlg-shared-title"]').text()).toContain('6 台')
  })

  it('409 台數已變：說明句 from=7 to=8、修正鈕以 8 重送', async () => {
    const w = await toShared()
    await w.get('[data-test="dlg-shared-check"] input').setValue(true)
    putMock.mockRejectedValueOnce(err409('RULE_EXECUTOR_SHARED_HOST_COUNT', { params: { count: 8 } }))
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="dlg-error-text"]').text()).toContain('台數從 7 台變成 8 台')
    expect(w.get('[data-test="dlg-fix"]').text()).toContain('確認 8 台並設定')
    putMock.mockResolvedValueOnce({})
    await w.get('[data-test="dlg-fix"]').trigger('click')
    await flushPromises()
    expect(putMock).toHaveBeenLastCalledWith(5, expect.objectContaining({ source: 'shared', acknowledged_host_count: 8 }))
  })

  it('用途不一致錯誤在憑證欄下方，修正鈕改用平台產生金鑰', async () => {
    const w = await toShared()
    await w.get('[data-test="dlg-shared-check"] input').setValue(true)
    putMock.mockRejectedValueOnce(err409('RULE_CREDENTIAL_PURPOSE_MISMATCH'))
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="dlg-error"]').attributes('data-placement')).toBe('field-credential')
    await w.get('[data-test="dlg-fix"]').trigger('click')
    expect(w.vm.source).toBe('generate')
  })

  it('Windows 族的金鑰型選項停用、人員連線用的停用', async () => {
    const w = await mountDialog({ windowsFamily: true })
    await w.get('[data-test="source-card-shared"]').trigger('click')
    await flushPromises()
    const picker = w.getComponent(CredentialPicker)
    expect(picker.vm.optionDisabledReason(KEYCRED())).toContain('Windows 主機只能用密碼')
    expect(picker.vm.optionDisabledReason(PWDCRED({ purpose: 'login' }))).toContain('人員連線用')
    expect(picker.vm.optionDisabledReason(PWDCRED())).toBe('')
  })
})

describe('ExecutorSharedDisclosure', () => {
  for (const lang of ['zh-TW', 'en-US', 'ja-JP']) {
    it(`${lang}：揭露句鍵齊全、金鑰版與密碼版標題不同、不含資產名稱`, () => {
      const ae = JSON.parse(readFileSync(join(__dirname, `../../../i18n/locales/${lang}.json`), 'utf8')).assetExecutor.sharedConfirm
      expect(ae.rotateSend).toContain('{count}')
      expect(ae.adviceKey.length).toBeGreaterThan(5)
      expect(ae.titleKey).not.toBe(ae.titlePassword)
      for (const v of Object.values(ae)) expect(v).not.toMatch(/web-0\d/)
    })
  }

  it('密碼型渲染含「送到這 7 台的每一台」與建議句；金鑰型無代改送出句', async () => {
    listCredsMock.mockResolvedValue({ data: [PWDCRED(), KEYCRED()] })
    const w = await mountDialog()
    await w.get('[data-test="source-card-shared"]').trigger('click')
    await flushPromises()
    w.getComponent(CredentialPicker).vm.$emit('update:modelValue', 32)
    await flushPromises()
    expect(w.get('[data-test="dlg-shared-body"]').text()).toContain('送到這 7 台的每一台')
    // 建議句另起一行（畫面稿 C1），不併在內文同段
    expect(w.get('[data-test="dlg-shared-advice"]').text()).toContain('建議改用平台產生的金鑰')
    expect(w.get('[data-test="dlg-shared-body"]').text()).not.toContain('建議改用')
    w.getComponent(CredentialPicker).vm.$emit('update:modelValue', 31)
    await flushPromises()
    expect(w.get('[data-test="dlg-shared-body"]').text()).not.toContain('送到這')
    expect(w.get('[data-test="dlg-shared-title"]').text()).toContain('這把金鑰')
    expect(w.text()).not.toContain('web-01')
  })
})

describe('ExecutorConvert', () => {
  async function toConvert() {
    const w = await mountDialog()
    await w.get('[data-test="source-convert-link"]').trigger('click')
    await flushPromises()
    return w
  }

  it('帳號清單載入；選定後三件事以 1. 2. 3. 開頭、無圈號', async () => {
    const w = await toConvert()
    expect(w.vm.accounts.length).toBe(3)
    w.vm.convertAccountId = 2
    await flushPromises()
    const effects = w.get('[data-test="dlg-convert-effects"]').text()
    expect(effects).toMatch(/1\. .*2\. .*3\. /)
    expect(effects).not.toMatch(/[①-⑳]/)
  })

  const cases = [
    ['RULE_EXECUTOR_CONVERT_CANDIDATE_PENDING', '新密碼還在等驗證', '/change-secret-plans'],
    ['RULE_CREDENTIAL_ROTATION_ACTIVE', '的密碼正在改', '/credentials?credential=12'],
    ['RULE_CREDENTIAL_OUT_OF_SYNC', '上一輪改密還有主機沒改完', '/credentials'],
  ]
  for (const [code, text, url] of cases) {
    it(`${code} 的句子、新分頁開啟與重新檢查`, async () => {
      const open = vi.spyOn(window, 'open').mockImplementation(() => null)
      const w = await toConvert()
      w.vm.convertAccountId = 2
      await flushPromises()
      putMock.mockRejectedValueOnce(err409(code))
      await w.get('[data-test="dlg-submit"]').trigger('click')
      await flushPromises()
      expect(w.get('[data-test="dlg-error-text"]').text()).toContain(text)
      await w.get('[data-test="dlg-fix"]').trigger('click')
      expect(open).toHaveBeenCalledWith(url, '_blank', 'noopener')
      putMock.mockResolvedValueOnce({})
      await w.get('[data-test="dlg-recheck"]').trigger('click')
      await flushPromises()
      expect(putMock).toHaveBeenLastCalledWith(5, { source: 'convert', account_id: 2, expected_account_id: 0 })
      open.mockRestore()
    })
  }

  it('返回後先前填的帳號名稱仍在；成功送出 convert 並 emit done', async () => {
    const w = await mountDialog()
    await w.get('input[data-test="dlg-username"]').setValue('keep-me')
    await w.get('[data-test="source-convert-link"]').trigger('click')
    await flushPromises()
    await w.get('[data-test="dlg-back"]').trigger('click')
    expect(w.vm.username).toBe('keep-me')
    await w.get('[data-test="source-convert-link"]').trigger('click')
    await flushPromises()
    w.vm.convertAccountId = 2
    await flushPromises()
    await w.get('[data-test="dlg-submit"]').trigger('click')
    await flushPromises()
    expect(w.emitted('done')[0][0]).toEqual({ kind: 'convert' })
  })
})
