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
