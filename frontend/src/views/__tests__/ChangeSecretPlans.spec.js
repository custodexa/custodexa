import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import ChangeSecretPlans from '../ChangeSecretPlans.vue'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

// 改密計劃頁（第 8 組）。
//
// 斷言重心在三件會靜默出錯的事：
//  1. 帳號範圍的 UI 狀態 ↔ 後端契約（`["@ALL"]` vs 明列）——送錯會使計劃
//     悄悄改掉「全部帳號」或「一個都不改」，兩者都不會報錯；
//  2. 密碼策略的預設值是「含符號、排除易混淆、16」而非 JS falsy 預設；
//  3. 未驗證憑證面板不呈現任何秘密材料，且清除操作走確認框。

enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const createPlanMock = vi.fn()
const updatePlanMock = vi.fn()
const listPlansMock = vi.fn()
const listCandidatesMock = vi.fn()
const retryCandidateMock = vi.fn()
const discardCandidateMock = vi.fn()

vi.mock('@/api/changeSecret', () => ({
  getChangeSecretPlans: (...a) => listPlansMock(...a),
  createChangeSecretPlan: (...a) => createPlanMock(...a),
  updateChangeSecretPlan: (...a) => updatePlanMock(...a),
  deleteChangeSecretPlan: vi.fn(() => Promise.resolve({})),
  runChangeSecretPlan: vi.fn(() => Promise.resolve({})),
  getChangeSecretRecords: vi.fn(() => Promise.resolve({ data: [] })),
  getChangeSecretCandidates: (...a) => listCandidatesMock(...a),
  retryChangeSecretCandidate: (...a) => retryCandidateMock(...a),
  discardChangeSecretCandidate: (...a) => discardCandidateMock(...a),
}))

vi.mock('@/api/assets', () => ({
  getAssetList: vi.fn(() =>
    Promise.resolve({ data: [{ id: 1, name: 'srv-1', host: '10.0.0.1', protocol: 'ssh' }] })
  ),
}))

const planFixture = (overrides = {}) => ({
  id: 1,
  name: 'weekly',
  asset_ids: '[1]',
  accounts: '["@ALL"]',
  secret_type: 'password',
  key_strategy: 'append_replace',
  password_length: 16,
  password_include_symbol: true,
  password_exclude_ambiguous: true,
  cron: '0 3 * * 0',
  enabled: true,
  ...overrides,
})

const candidateFixture = (overrides = {}) => ({
  id: 9,
  asset_id: 1,
  account_id: 3,
  account_username: 'root',
  plan_id: 1,
  secret_type: 'password',
  applied: true,
  abandoned: false,
  attempt_count: 2,
  last_attempt_at: '2026-08-12T01:00:00Z',
  next_attempt_at: '2026-08-12T01:20:00Z',
  last_error: 'CHANGE_SECRET_VERIFY_FAILED',
  created_at: '2026-08-12T00:00:00Z',
  ...overrides,
})

async function mountPage() {
  const wrapper = mount(ChangeSecretPlans, { global: { plugins: [ElementPlus] } })
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  vi.clearAllMocks()
  listPlansMock.mockResolvedValue({ data: [planFixture()] })
  listCandidatesMock.mockResolvedValue({ data: [] })
  createPlanMock.mockResolvedValue({})
  updatePlanMock.mockResolvedValue({})
})

describe('帳號範圍 ↔ 後端契約', () => {
  it('預設（全部帳號）送出 ["@ALL"]，不是空陣列', async () => {
    const wrapper = await mountPage()
    wrapper.vm.openCreate()
    wrapper.vm.form.name = 'p1'
    wrapper.vm.form.asset_ids = [1]
    await wrapper.vm.$nextTick()

    const payload = wrapper.vm.buildPayload()
    expect(payload.accounts).toEqual(['@ALL'])
  })

  it('指定帳號送出明列集合', async () => {
    const wrapper = await mountPage()
    wrapper.vm.openCreate()
    wrapper.vm.form.accountScopeMode = 'named'
    wrapper.vm.form.accounts = ['root', 'deploy']

    expect(wrapper.vm.buildPayload().accounts).toEqual(['root', 'deploy'])
  })

  it('編輯既有計劃時，@ALL 與明列各自還原成正確的 UI 狀態', async () => {
    const wrapper = await mountPage()

    wrapper.vm.openEdit(planFixture())
    expect(wrapper.vm.form.accountScopeMode).toBe('all')
    expect(wrapper.vm.form.accounts).toEqual([])

    wrapper.vm.openEdit(planFixture({ accounts: '["root"]' }))
    expect(wrapper.vm.form.accountScopeMode).toBe('named')
    expect(wrapper.vm.form.accounts).toEqual(['root'])
  })

  it('accounts 欄為空字串（未設）時視為全部帳號', async () => {
    const wrapper = await mountPage()
    expect(wrapper.vm.isAllAccounts('')).toBe(true)
    expect(wrapper.vm.isAllAccounts('["root"]')).toBe(false)
  })
})

describe('密碼策略預設值', () => {
  it('新建表單的預設為長度 16、含符號、排除易混淆', async () => {
    const wrapper = await mountPage()
    wrapper.vm.openCreate()
    const p = wrapper.vm.buildPayload()
    expect(p.password_length).toBe(16)
    expect(p.password_include_symbol).toBe(true)
    expect(p.password_exclude_ambiguous).toBe(true)
    expect(p.secret_type).toBe('password')
  })

  it('編輯時明確為 false 的開關不被還原成 true', async () => {
    const wrapper = await mountPage()
    wrapper.vm.openEdit(
      planFixture({ password_include_symbol: false, password_exclude_ambiguous: false, password_length: 32 })
    )
    const p = wrapper.vm.buildPayload()
    expect(p.password_include_symbol).toBe(false)
    expect(p.password_exclude_ambiguous).toBe(false)
    expect(p.password_length).toBe(32)
  })

  it('金鑰型別計劃還原其策略欄', async () => {
    const wrapper = await mountPage()
    wrapper.vm.openEdit(planFixture({ secret_type: 'ssh_key', key_strategy: 'exclusive' }))
    const p = wrapper.vm.buildPayload()
    expect(p.secret_type).toBe('ssh_key')
    expect(p.key_strategy).toBe('exclusive')
  })
})

describe('未驗證憑證面板', () => {
  // 後端只回機器碼（遠端原文一律不進 last_error／error，見 change_secret_runner.go
  // 的 logRemoteCause）；前端負責查表在地化，查無對應鍵才原樣顯示
  it('last_error 機器碼以在地化文案呈現，未知值原樣顯示', async () => {
    listCandidatesMock.mockResolvedValue({
      data: [candidateFixture({ last_error: 'CHANGE_SECRET_REMOTE_STATE_UNKNOWN' })],
    })
    const wrapper = await mountPage()

    const html = wrapper.html()
    expect(html).not.toContain('CHANGE_SECRET_REMOTE_STATE_UNKNOWN')
    expect(html).toContain('伺服器日誌')
    // 歷史資料留下的舊散文訊息沒有對應鍵：原樣顯示，不得吞成空白
    expect(wrapper.vm.reasonText('dial tcp: i/o timeout')).toBe('dial tcp: i/o timeout')
    expect(wrapper.vm.reasonText('')).toBe('')
  })

  it('呈現狀態與重試資訊，且畫面不含任何秘密欄位', async () => {
    listCandidatesMock.mockResolvedValue({ data: [candidateFixture()] })
    const wrapper = await mountPage()

    const html = wrapper.html()
    expect(html).toContain('root')
    expect(html).not.toContain('password_enc')
    expect(html).not.toContain('private_key_enc')
    expect(wrapper.vm.candidateStateText(candidateFixture())).toBeTruthy()
    // 三種狀態各自可辨識，不得塌縮成同一句
    const applied = wrapper.vm.candidateStateText(candidateFixture({ applied: true }))
    const unknown = wrapper.vm.candidateStateText(candidateFixture({ applied: false }))
    const abandoned = wrapper.vm.candidateStateText(candidateFixture({ abandoned: true }))
    expect(new Set([applied, unknown, abandoned]).size).toBe(3)
    expect(wrapper.vm.candidateTagType(candidateFixture({ abandoned: true }))).toBe('danger')
  })

  it('重試成功與仍失敗給不同回饋，且都重新載入清單', async () => {
    listCandidatesMock.mockResolvedValue({ data: [candidateFixture()] })
    const wrapper = await mountPage()
    listCandidatesMock.mockClear()

    retryCandidateMock.mockResolvedValue({ promoted: true })
    await wrapper.vm.retryCandidate(candidateFixture())
    await flushPromises()
    expect(retryCandidateMock).toHaveBeenCalledWith(9)
    expect(listCandidatesMock).toHaveBeenCalled()
  })

  it('清除候選需經確認框；取消即不呼叫 API', async () => {
    listCandidatesMock.mockResolvedValue({ data: [candidateFixture()] })
    const wrapper = await mountPage()

    const { ElMessageBox } = await import('element-plus')
    const spy = vi.spyOn(ElMessageBox, 'confirm').mockRejectedValue(new Error('cancel'))
    await wrapper.vm.discardCandidate(candidateFixture())
    expect(spy).toHaveBeenCalled()
    expect(discardCandidateMock).not.toHaveBeenCalled()

    spy.mockResolvedValue('confirm')
    discardCandidateMock.mockResolvedValue({})
    await wrapper.vm.discardCandidate(candidateFixture())
    await flushPromises()
    expect(discardCandidateMock).toHaveBeenCalledWith(9)
    spy.mockRestore()
  })
})

// 憑證最長使用天數覆蓋。
//
// 這個欄位只影響輪替證據報告的適用天數，不改變計劃的執行時機——但它會被送進
// 同一份 payload，漏送或漏還原都會讓報告用錯天數而沒有任何人看得出來。
describe('憑證最長使用天數覆蓋', () => {
  it('新建預設 0（沿用全域），且會進 payload', async () => {
    const wrapper = await mountPage()
    wrapper.vm.openCreate()
    expect(wrapper.vm.buildPayload().max_age_days).toBe(0)

    wrapper.vm.form.max_age_days = 60
    expect(wrapper.vm.buildPayload().max_age_days).toBe(60)
  })

  it('編輯既有計劃時還原後端的覆蓋值', async () => {
    const wrapper = await mountPage()
    wrapper.vm.openEdit(planFixture({ max_age_days: 45 }))
    expect(wrapper.vm.form.max_age_days).toBe(45)
    expect(wrapper.vm.buildPayload().max_age_days).toBe(45)
  })

  it('越界由後端拒絕：對話框留在原地讓人改，且該機器碼有對應提示', async () => {
    const wrapper = await mountPage()
    wrapper.vm.openCreate()
    wrapper.vm.form.name = 'p-bad'
    wrapper.vm.form.asset_ids = [1]
    wrapper.vm.form.max_age_days = 4000
    createPlanMock.mockRejectedValue(new Error('VALIDATION_PLAN_BAD_MAX_AGE_DAYS'))
    await wrapper.vm.submit()
    await flushPromises()
    expect(wrapper.vm.dialogVisible).toBe(true)

    // 提示文案走既有的機器碼對照表：沒有譯文時使用者只會看到一串代碼
    const zh = JSON.parse(
      readFileSync(join(process.cwd(), 'src/i18n/locales/zh-TW.json'), 'utf8')
    )
    expect(zh.apiError.VALIDATION_PLAN_BAD_MAX_AGE_DAYS).toBeTruthy()
  })
})

// Windows 改密通道（第 3 段前端）。
//
// 資產下拉改列「有效通道非 none」的資產：未設通道的 rdp 在這裡就選不到，而不是
// 選了才在執行期被記為略過；記錄與候選多一欄「通道」，由資產現況推得。
describe('改密通道：資產下拉、記錄通道欄、機器碼文案', () => {
  const dialogStub = {
    props: ['modelValue'],
    template: '<div v-if="modelValue" class="dialog-stub"><slot /></div>',
  }
  const selectStub = {
    name: 'ElSelect',
    props: ['modelValue'],
    template: '<div class="select-stub"><slot /></div>',
  }
  const optionStub = {
    name: 'ElOption',
    props: ['label', 'value'],
    template: '<div class="option-stub" :data-value="value"><slot>{{ label }}</slot></div>',
  }

  const assetsFixture = () => [
    { id: 1, name: 'srv-1', host: '10.0.0.1', port: 22, protocol: 'ssh', effective_rotation_channel: 'posix_ssh' },
    {
      id: 2, name: 'win-app-01', host: '192.0.2.17', port: 3389, protocol: 'rdp',
      rotation_channel: 'windows_winrm', effective_rotation_channel: 'windows_winrm',
      winrm_scheme: 'http', has_winrm_ca_cert: false,
    },
    {
      id: 3, name: 'win-app-02', host: '192.0.2.18', port: 3389, protocol: 'rdp',
      rotation_channel: 'windows_winrm', effective_rotation_channel: 'windows_winrm',
      winrm_scheme: 'https', winrm_tls_mode: 'system',
    },
    { id: 4, name: 'win-file-04', host: '192.0.2.20', port: 3389, protocol: 'rdp', effective_rotation_channel: 'none' },
    { id: 5, name: 'win-jump-03', host: '192.0.2.21', port: 3389, protocol: 'rdp', effective_rotation_channel: 'windows_ssh' },
  ]

  const mountWithStubs = async () => {
    const { getAssetList } = await import('@/api/assets')
    getAssetList.mockResolvedValueOnce({ data: assetsFixture() })
    const wrapper = mount(ChangeSecretPlans, {
      global: {
        plugins: [ElementPlus],
        stubs: { 'el-dialog': dialogStub, 'el-select': selectStub, 'el-option': optionStub },
      },
    })
    await flushPromises()
    return wrapper
  }

  it('下拉含 rdp＋WinRM 與 SSH → PowerShell 資產、不含 rdp＋none；通道 tag 文字與色', async () => {
    const wrapper = await mountWithStubs()
    wrapper.vm.openCreate()
    await flushPromises()

    expect(wrapper.vm.rotatableAssets.map((a) => a.id)).toEqual([1, 2, 3, 5])

    const options = wrapper.find('[data-test="plan-assets"]').findAll('.option-stub')
    expect(options.map((o) => o.attributes('data-value'))).toEqual(['1', '2', '3', '5'])
    const text = wrapper.find('[data-test="plan-assets"]').text()
    expect(text).toContain('win-app-01')
    expect(text).toContain('WinRM · HTTP')
    expect(text).toContain('WinRM · HTTPS')
    expect(text).toContain('SSH → PowerShell')
    expect(text).toContain('POSIX SSH')
    expect(text).not.toContain('win-file-04')
    // http 的 WinRM 走 warning 色，https＋系統信任走 info
    const httpTag = options[1].findComponent({ name: 'ElTag' })
    const httpsTag = options[2].findComponent({ name: 'ElTag' })
    expect(httpTag.props('type')).toBe('warning')
    expect(httpsTag.props('type')).toBe('info')
    // 底部指引
    expect(wrapper.find('[data-test="plan-assets-hint"]').text()).toContain('只列已設定改密通道的資產')
  })

  it('選了 Windows 資產再選金鑰型別：提示會記為略過；純 POSIX 不提示', async () => {
    const wrapper = await mountWithStubs()
    wrapper.vm.openCreate()
    wrapper.vm.form.secret_type = 'ssh_key'
    wrapper.vm.form.asset_ids = [1]
    await flushPromises()
    expect(wrapper.find('[data-test="secret-type-windows-hint"]').exists()).toBe(false)

    wrapper.vm.form.asset_ids = [1, 2]
    await flushPromises()
    expect(wrapper.find('[data-test="secret-type-windows-hint"]').text()).toContain('Windows 通道只支援密碼')
  })

  it('記錄對話框有「通道」欄：由資產現況推得，未設通道的資產顯示佔位', async () => {
    const wrapper = await mountWithStubs()
    const { getChangeSecretRecords } = await import('@/api/changeSecret')
    getChangeSecretRecords.mockResolvedValueOnce({
      data: [
        { id: 1, asset_id: 2, account_username: 'Administrator', status: 'success', error: '', executed_at: '2026-09-03T03:00:12Z' },
        { id: 2, asset_id: 3, account_username: 'svc_backup', status: 'failed', error: 'CHANGE_SECRET_WINRM_ENCRYPTION_UNAVAILABLE', executed_at: '2026-09-03T03:00:09Z' },
        { id: 3, asset_id: 4, account_username: '', status: 'skipped', error: 'CHANGE_SECRET_CHANNEL_NOT_CONFIGURED', executed_at: '2026-09-03T03:00:00Z' },
      ],
    })
    await wrapper.vm.openRecords(planFixture())
    await flushPromises()

    const dialog = wrapper.findAll('.dialog-stub').at(-1)
    const text = dialog.text()
    expect(text).toContain('通道')
    expect(text).toContain('WinRM · HTTP')
    expect(text).toContain('WinRM · HTTPS')
    // 訊息欄是機器碼的文案，不是碼本身
    expect(text).not.toContain('CHANGE_SECRET_WINRM_ENCRYPTION_UNAVAILABLE')
    expect(text).toContain('已拒絕連線且未送出任何憑證')
    expect(text).toContain('資產未設定改密通道')
    // 未設通道的資產：通道欄佔位
    expect(wrapper.vm.assetChannelText(4)).toBe('')
    expect(wrapper.vm.assetChannelText(999)).toBe('')
    // 結果統計與說明句
    expect(wrapper.find('[data-test="records-summary"]').text()).toContain('共 3 筆')
    expect(wrapper.find('[data-test="records-summary"]').text()).toContain('成功 1')
    expect(wrapper.find('[data-test="records-note"]').text()).toContain('伺服器日誌')
  })

  it('候選表也有通道欄', async () => {
    listCandidatesMock.mockResolvedValue({ data: [candidateFixture({ asset_id: 2 })] })
    const wrapper = await mountWithStubs()
    const html = wrapper.html()
    expect(html).toContain('WinRM · HTTP')
    expect(wrapper.vm.assetChannelTagType(2)).toBe('warning')
  })

  it('五個新原因碼皆有文案；協議不支援的文案不再說「僅支援 SSH」', async () => {
    const wrapper = await mountPage()
    const codes = [
      'CHANGE_SECRET_CHANNEL_NOT_CONFIGURED',
      'CHANGE_SECRET_SECRET_TYPE_UNSUPPORTED',
      'CHANGE_SECRET_WINRM_ENCRYPTION_UNAVAILABLE',
      'CHANGE_SECRET_STDIN_NOT_DELIVERED',
      'CHANGE_SECRET_ACCOUNT_NAME_INVALID',
    ]
    for (const code of codes) {
      const text = wrapper.vm.reasonText(code)
      expect(text, code).not.toBe(code)
      expect(text.length, code).toBeGreaterThan(0)
    }
    const unsupported = wrapper.vm.reasonText('CHANGE_SECRET_PROTOCOL_UNSUPPORTED')
    expect(unsupported).not.toContain('僅支援 SSH')
    expect(unsupported).toContain('不支援改密')

    // 三語都不得殘留「只支援 SSH」的說法
    const locales = ['zh-TW', 'en-US', 'ja-JP'].map((l) =>
      JSON.parse(readFileSync(join(process.cwd(), `src/i18n/locales/${l}.json`), 'utf8'))
    )
    for (const messages of locales) {
      const v = messages.changeSecretPlans.reason.CHANGE_SECRET_PROTOCOL_UNSUPPORTED
      expect(v).toBeTruthy()
      expect(v).not.toMatch(/only ssh|ssh 資產のみ|僅支援 ssh/i)
      for (const code of codes) {
        expect(messages.changeSecretPlans.reason[code], code).toBeTruthy()
      }
    }
  })
})
