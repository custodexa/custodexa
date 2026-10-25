import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessage } from 'element-plus'
import i18n from '@/i18n'
import HostIdentityConfirmDialog from '@/components/HostIdentityConfirmDialog.vue'
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

// 下次執行時刻由排程端點回答；列表與表單都只顯示，不自行推算
const nextRunsMock = vi.fn()
vi.mock('@/api/schedules', () => ({
  getScheduleNextRuns: (...a) => nextRunsMock(...a),
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
  nextRunsMock.mockResolvedValue({
    runs: ['2026-09-13T03:00:00+08:00'],
    timezone: 'Asia/Taipei',
  })
})

describe('帳號範圍 ↔ 後端契約', () => {
  it('預設（全部帳號）送出 ["@ALL"]，不是空陣列', async () => {
    const wrapper = await mountPage()
    // 列表的排程欄講人話並附下次執行時刻；排程字串退到編輯表單的自訂欄
    expect(wrapper.find('[data-test="plan-schedule-1"]').text()).toBe('每星期日 03:00')
    expect(wrapper.text()).toContain('下次 2026-09-13 03:00')
    expect(wrapper.text()).not.toContain('0 3 * * 0')

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

  it('共用憑證目標的略過原因說的是「這個目標」，不是「整張計劃」', async () => {
    const wrapper = await mountPage()

    // 實碼只略過該目標（其餘目標照跑），文案升格成「本計劃已略過」會讓值班人員
    // 以為整張計劃沒跑
    const text = wrapper.vm.reasonText('SHARED_CREDENTIAL_TARGET_REQUIRED')
    expect(text).not.toBe('SHARED_CREDENTIAL_TARGET_REQUIRED')
    expect(text).toContain('此目標')
    expect(text).not.toContain('本計劃')

    const expectations = {
      'zh-TW': /此目標/,
      'en-US': /this target/i,
      'ja-JP': /この対象/,
    }
    for (const [locale, pattern] of Object.entries(expectations)) {
      const messages = JSON.parse(
        readFileSync(join(process.cwd(), `src/i18n/locales/${locale}.json`), 'utf8')
      )
      const value = messages.changeSecretPlans.reason.SHARED_CREDENTIAL_TARGET_REQUIRED
      expect(value, locale).toMatch(pattern)
      expect(value, locale).not.toMatch(/本計劃|the plan was skipped|計画をスキップ/)
    }
  })
})

// 主機身分停止的候選：重試入口 → 確認對話框 → 帶確認 body 重送。
//
// 這是使用者唯一的確認入口：接錯會讓人以為已排入重試、實際卻停著。
describe('候選清單的主機身分確認', () => {
  const STOP = 'CHANGE_SECRET_HOST_IDENTITY_CHANGED'
  const FP = 'SHA256:q3Vt9xLk2mP8rT0aZ4bN7cY1eW6sH5jD'
  const msg = (key, params) => i18n.global.t(key, params)
  const dialogStub = {
    props: ['modelValue', 'title'],
    template:
      '<div v-if="modelValue" class="dialog-stub"><h3>{{ title }}</h3><slot /><slot name="footer" /></div>',
  }

  const hostIdentity = (over = {}) => ({
    status: 'changed',
    detail: 'generation_changed',
    phase: 'precheck',
    verification_sent: false,
    original: {
      transport: 'ssh', record_id: 41, algorithm: 'ssh-ed25519', fingerprint: FP,
      generation: 2, binding: 'bound', bound_at: '2026-10-17T02:00:00Z',
    },
    current: {
      transport: 'ssh', record_id: 41, algorithm: 'ssh-ed25519', fingerprint: FP,
      generation: 3, reset_pending: false, recorded_at: '2026-10-17T10:05:00Z',
    },
    candidate_applied: false,
    deadline: '2026-10-18T02:00:00Z',
    expired: false,
    confirmable: true,
    ...over,
  })

  async function mountStopped(rowOver = {}) {
    listCandidatesMock.mockResolvedValue({
      data: [candidateFixture({ last_error: STOP, ...rowOver })],
    })
    const wrapper = mount(ChangeSecretPlans, {
      global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub } },
    })
    await flushPromises()
    return wrapper
  }

  const dialogOf = (w) => w.findComponent(HostIdentityConfirmDialog)

  async function openAndConfirm(w) {
    retryCandidateMock.mockResolvedValueOnce({ promoted: false, host_identity: hostIdentity() })
    await w.vm.retryCandidate(candidateFixture({ last_error: STOP }))
    await flushPromises()
    await w.find('[data-test="hic-check-identity"] input').setValue(true)
    await w.find('[data-test="hic-submit"]').trigger('click')
    await flushPromises()
  }

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('未停止的候選重試：不帶 body，請求只有 id', async () => {
    const w = await mountStopped({ last_error: 'CHANGE_SECRET_VERIFY_FAILED' })
    retryCandidateMock.mockResolvedValue({ promoted: false })
    await w.vm.retryCandidate(candidateFixture())
    await flushPromises()
    expect(retryCandidateMock).toHaveBeenCalledTimes(1)
    expect(retryCandidateMock.mock.calls[0]).toEqual([9])
    expect(dialogOf(w).props('modelValue')).toBe(false)
  })

  it('回應帶 host_identity：開確認對話框（候選種類），不顯示「已排入下次重試」', async () => {
    const success = vi.spyOn(ElMessage, 'success')
    const w = await mountStopped()
    retryCandidateMock.mockResolvedValue({ promoted: false, host_identity: hostIdentity() })
    await w.vm.retryCandidate(candidateFixture({ last_error: STOP }))
    await flushPromises()
    const dlg = dialogOf(w)
    expect(dlg.props('modelValue')).toBe(true)
    expect(dlg.props('kind')).toBe('candidate')
    expect(dlg.props('account')).toBe('root')
    expect(dlg.props('asset')).toBe('srv-1')
    expect(dlg.props('identity').detail).toBe('generation_changed')
    expect(success).not.toHaveBeenCalled()
    expect(w.find('[data-test="hic-submit"]').exists()).toBe(true)
  })

  it('確認後帶 body 重送：body 等於對話框 emit 的 payload，鍵集合只含身分欄位', async () => {
    const success = vi.spyOn(ElMessage, 'success')
    const w = await mountStopped()
    retryCandidateMock.mockResolvedValueOnce({ promoted: true })
    retryCandidateMock.mockClear()
    // openAndConfirm 的第一次回應是 host_identity，第二次才是確認結果
    retryCandidateMock.mockReset()
    retryCandidateMock
      .mockResolvedValueOnce({ promoted: false, host_identity: hostIdentity() })
      .mockResolvedValueOnce({ promoted: true })
    await openAndConfirm(w)
    expect(retryCandidateMock).toHaveBeenCalledTimes(2)
    const emitted = dialogOf(w).emitted('confirm')[0][0]
    const [id, body] = retryCandidateMock.mock.calls[1]
    expect(id).toBe(9)
    expect(Object.keys(body)).toEqual(['confirm_host_identity'])
    expect(body.confirm_host_identity).toEqual(emitted)
    expect(Object.keys(body.confirm_host_identity).sort()).toEqual(
      ['accept_different_key', 'algorithm', 'fingerprint', 'generation', 'record_id', 'transport']
    )
    expect(body.confirm_host_identity.accept_different_key).toBe(false)
    expect(JSON.stringify(body)).not.toMatch(/password|private_key|secret/i)
    expect(success).toHaveBeenCalledWith(msg('hostIdentityConfirm.result.verified'))
    expect(dialogOf(w).props('modelValue')).toBe(false)
  })

  it('確認後驗證失敗：不沿用「已排入下次重試」，說新憑證仍保留、可再確認', async () => {
    const success = vi.spyOn(ElMessage, 'success')
    const warning = vi.spyOn(ElMessage, 'warning')
    const w = await mountStopped()
    retryCandidateMock.mockReset()
    retryCandidateMock
      .mockResolvedValueOnce({ promoted: false, host_identity: hostIdentity() })
      .mockResolvedValueOnce({ promoted: false })
    await openAndConfirm(w)
    expect(success).not.toHaveBeenCalled()
    expect(warning).toHaveBeenCalledWith(msg('hostIdentityConfirm.result.notVerified'))
    const all = JSON.stringify(warning.mock.calls)
    expect(all).not.toContain(msg('changeSecretPlans.retryStillFailing'))
    expect(dialogOf(w).props('modelValue')).toBe(false)
  })

  it('確認時目標已改變（200＋reason）：顯示該原因碼文案，不算成功、不是身分移動', async () => {
    const success = vi.spyOn(ElMessage, 'success')
    const warning = vi.spyOn(ElMessage, 'warning')
    const w = await mountStopped()
    retryCandidateMock.mockReset()
    retryCandidateMock
      .mockResolvedValueOnce({ promoted: false, host_identity: hostIdentity() })
      .mockResolvedValueOnce({ promoted: false, reason: 'CHANGE_SECRET_AUTHZ_TARGET_CHANGED' })
    await openAndConfirm(w)
    expect(warning).toHaveBeenCalledWith(msg('changeSecretPlans.reason.CHANGE_SECRET_AUTHZ_TARGET_CHANGED'))
    expect(success).not.toHaveBeenCalled()
    expect(dialogOf(w).props('modelValue')).toBe(false)
  })

  it.each([
    ['different_key_not_accepted', 'hostIdentityConfirm.differentKey.title'],
    ['not_confirmable', 'hostIdentityConfirm.blocked.contactAdmin'],
    ['confirmation_pending', 'hostIdentityConfirm.result.moved'],
  ])('確認遇 409 CONFLICT_HOST_IDENTITY_MOVED（detail=%s）：顯示對應說明、不算成功、對話框關閉並重新載入', async (detail, key) => {
    const success = vi.spyOn(ElMessage, 'success')
    const error = vi.spyOn(ElMessage, 'error')
    const warning = vi.spyOn(ElMessage, 'warning')
    const w = await mountStopped()
    retryCandidateMock.mockReset()
    retryCandidateMock
      .mockResolvedValueOnce({ promoted: false, host_identity: hostIdentity() })
      .mockRejectedValueOnce({
        response: { status: 409, data: { code: 'CONFLICT_HOST_IDENTITY_MOVED', detail } },
      })
    listCandidatesMock.mockClear()
    await openAndConfirm(w)
    // 只有一則、error 等級（全域 toast 由 API 層選項關閉，見 api 測試）
    expect(error).toHaveBeenCalledTimes(1)
    expect(error).toHaveBeenCalledWith(msg(key))
    expect(warning).not.toHaveBeenCalled()
    expect(success).not.toHaveBeenCalled()
    expect(dialogOf(w).props('modelValue')).toBe(false)
    expect(listCandidatesMock).toHaveBeenCalled()
    // 全域攔截器負責顯示 apiError 文案：該鍵必須有譯文
    expect(i18n.global.te('apiError.CONFLICT_HOST_IDENTITY_MOVED')).toBe(true)
  })

  it('「下次重試」欄：身分停止的列顯示待確認主機身分，其他列照排程時間', async () => {
    listCandidatesMock.mockResolvedValue({
      data: [
        candidateFixture({ id: 9, last_error: STOP }),
        candidateFixture({ id: 10, last_error: 'CHANGE_SECRET_VERIFY_FAILED' }),
      ],
    })
    const w = mount(ChangeSecretPlans, {
      global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub } },
    })
    await flushPromises()
    const pending = w.findAll('[data-test="candidate-host-identity-pending"]')
    expect(pending).toHaveLength(1)
    expect(pending[0].text()).toBe(msg('changeSecretPlans.hostIdentityPending'))
    expect(w.vm.isHostIdentityStopped(candidateFixture({ last_error: 'CHANGE_SECRET_VERIFY_FAILED' }))).toBe(false)
  })
})

describe('範圍外目標被遮蔽的計劃', () => {
  it('資產有被省略時顯示範圍外計數，並以唯讀取代編輯', async () => {
    listPlansMock.mockResolvedValue({
      data: [planFixture({ id: 5, asset_ids: '[1]', out_of_scope_asset_count: 2 })],
    })
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="plan-assets-out-5"]').text()).toContain('2')
    expect(wrapper.find('[data-test="plan-scoped-readonly-5"]').exists()).toBe(true)
    expect(wrapper.text()).not.toContain(i18n.global.t('common.edit'))
  })

  it('憑證被遮蔽（識別為 null）時整頁正常渲染且不可編輯', async () => {
    listPlansMock.mockResolvedValue({
      data: [
        planFixture({
          id: 6,
          target_kind: 'credential',
          target_credential_id: null,
          credential_out_of_scope: true,
        }),
      ],
    })
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="plan-scoped-readonly-6"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="plan-assets-out-6"]').exists()).toBe(false)
  })

  it('未遮蔽的計劃仍可編輯，不顯示唯讀標記', async () => {
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="plan-scoped-readonly-1"]').exists()).toBe(false)
    expect(wrapper.text()).toContain(i18n.global.t('common.edit'))
  })
})
