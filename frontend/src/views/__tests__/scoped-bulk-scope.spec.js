import { computed, ref } from 'vue'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessage } from 'element-plus'
import i18n, { setLanguage } from '@/i18n'
import zhTW from '@/i18n/locales/zh-TW.json'
import enUS from '@/i18n/locales/en-US.json'
import jaJP from '@/i18n/locales/ja-JP.json'
import AccountBatchRotation from '../AccountBatchRotation.vue'
import ChangeSecretPlans from '../ChangeSecretPlans.vue'
import BulkAssetTable from '@/components/asset/bulk/BulkAssetTable.vue'
import { resolveApiError } from '@/api/error'
import { useBulkErrorReport } from '@/composables/useBulkErrorReport'
import { newRow } from '@/utils/assetBulk'

// 範圍化管理者的批次改密、批次新增與改密計畫畫面。
//
// 前端只消費伺服器回應：批次無法操作只帶筆數、匯入兩個「不存在或無法使用」碼不分辨原因、
// 計畫暫停狀態與範圍外台數都取自回應。斷言重心：
//  1. 橫幅文字只含已選數與筆數，不含任何資產名；
//  2. 歸屬欄只在整批同一組模式送出，選項請求帶用途參數；
//  3. 兩個匯入專屬文字在錯誤清單、儲存格與下載 CSV 一致；
//  4. 上界暫停的計畫與「升級後無法確認發起者」分開呈現，確認只顯示台數。

enableAutoUnmount(afterEach)

class ObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', ObserverStub)
vi.stubGlobal('ResizeObserver', ObserverStub)
vi.setConfig({ testTimeout: 20_000 })

const usernamesMock = vi.fn()
const targetsMock = vi.fn()
const createBatchMock = vi.fn()
const listBatchesMock = vi.fn()
const getBatchMock = vi.fn()
vi.mock('@/api/changeSecretBatches', () => ({
  getChangeSecretBatchUsernames: (...a) => usernamesMock(...a),
  getChangeSecretBatchTargets: (...a) => targetsMock(...a),
  createChangeSecretBatch: (...a) => createBatchMock(...a),
  getChangeSecretBatches: (...a) => listBatchesMock(...a),
  getChangeSecretBatch: (...a) => getBatchMock(...a),
}))

const listPlansMock = vi.fn()
const updatePlanMock = vi.fn()
const createPlanMock = vi.fn()
vi.mock('@/api/changeSecret', () => ({
  getChangeSecretPlans: (...a) => listPlansMock(...a),
  createChangeSecretPlan: (...a) => createPlanMock(...a),
  updateChangeSecretPlan: (...a) => updatePlanMock(...a),
  deleteChangeSecretPlan: vi.fn(() => Promise.resolve({})),
  runChangeSecretPlan: vi.fn(() => Promise.resolve({})),
  getChangeSecretRecords: vi.fn(() => Promise.resolve({ data: [] })),
  getChangeSecretCandidates: vi.fn(() => Promise.resolve({ data: [] })),
  retryChangeSecretCandidate: vi.fn(),
  discardChangeSecretCandidate: vi.fn(),
  reauthorizeChangeSecretPlans: vi.fn(),
}))

const groupsMock = vi.fn()
vi.mock('@/api/assets', async (importOriginal) => ({
  ...(await importOriginal()),
  getAssetGroups: (...a) => groupsMock(...a),
  getAssetList: vi.fn(() =>
    Promise.resolve({ data: [{ id: 1, name: 'plan-host', host: '10.0.0.1', protocol: 'ssh' }] })
  ),
}))

const impactMock = vi.fn()
vi.mock('@/api/credentials', async (importOriginal) => ({
  ...(await importOriginal()),
  confirmCredentialImpact: (...a) => impactMock(...a),
}))

vi.mock('@/api/schedules', () => ({
  getScheduleNextRuns: vi.fn(() => Promise.resolve({ data: [] })),
}))

const dialogStub = {
  props: ['modelValue', 'title'],
  template:
    '<div v-if="modelValue" class="dialog-stub"><h3>{{ title }}</h3><slot /><slot name="footer" /></div>',
}

const LOCALES = { 'zh-TW': zhTW, 'en-US': enUS, 'ja-JP': jaJP }
const fill = (text, params) => text.replace(/\{(\w+)\}/g, (_, k) => String(params[k]))
const lookup = (messages, key) => key.split('.').reduce((o, k) => o[k], messages)

afterEach(() => setLanguage('zh-TW'))

// ---------------------------------------------------------------- 7.1 批次改密頁

const ASSET_NAMES = Array.from({ length: 24 }, (_, i) => `scope-host-${i + 1}`)

const targetFixture = (i) => ({
  account_id: i + 1,
  asset_id: 100 + i,
  asset_name: ASSET_NAMES[i],
  asset_address: `10.1.0.${i + 1}`,
  protocol: 'ssh',
  username: 'ops',
  credential_type: 'password',
  privileged: false,
  shared_credential: false,
  plans: [],
  multi_plan: false,
  max_age_days: 90,
  max_age_source: 'global',
  last_success_at: null,
  last_record_status: '',
  remaining_days_a: null,
  next_schedule_at: null,
  remaining_days_b: null,
  candidate_state: '',
  bucket: 'no_record',
  rotation_channel: 'posix_ssh',
  ineligible_reason: '',
})

const unavailableError = (count) => ({
  response: { status: 404, data: { code: 'NOTFOUND_BATCH_ITEMS_UNAVAILABLE', params: { count } } },
})

async function mountBatchPage() {
  const wrapper = mount(AccountBatchRotation, {
    global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub } },
  })
  await flushPromises()
  await wrapper.vm.selectUsername('ops')
  await flushPromises()
  return wrapper
}

function selectAll(wrapper) {
  for (let i = 0; i < 24; i++) wrapper.vm.toggleTarget(targetFixture(i))
}

beforeEach(() => {
  vi.clearAllMocks()
  usernamesMock.mockResolvedValue({ data: [{ username: 'ops', asset_count: 24 }], total: 1 })
  targetsMock.mockResolvedValue({ data: ASSET_NAMES.map((_, i) => targetFixture(i)), total: 24 })
  listBatchesMock.mockResolvedValue({ data: [], total: 0 })
  getBatchMock.mockResolvedValue({ data: { batch: { id: 7, status: 'running' }, records: [] } })
  createBatchMock.mockResolvedValue({ data: { id: 7, status: 'running', password_mode: 'per_target' } })
  groupsMock.mockResolvedValue({ data: [], total: 0 })
})

describe('批次改密頁：整批無法操作橫幅', () => {
  it.each(Object.keys(LOCALES))('%s：橫幅文字等於鍵插值結果，且不含任何資產名', async (locale) => {
    setLanguage(locale)
    const wrapper = await mountBatchPage()
    selectAll(wrapper)
    expect(wrapper.vm.selected).toHaveLength(24)
    createBatchMock.mockRejectedValueOnce(unavailableError(3))

    wrapper.vm.openBatch()
    await flushPromises()
    await wrapper.find('[data-test="submit-batch"]').trigger('click')
    await flushPromises()

    const banner = wrapper.find('[data-test="unavailable-banner"]')
    expect(banner.exists()).toBe(true)
    const expected = fill(lookup(LOCALES[locale], 'changeSecretBatches.unavailableBanner'), {
      selected: 24,
      count: 3,
    })
    expect(banner.find('.el-alert__title').text()).toBe(expected)
    expect(banner.find('[data-test="unavailable-refresh"]').text()).toBe(
      lookup(LOCALES[locale], 'common.refresh')
    )
    for (const name of ASSET_NAMES) expect(banner.text()).not.toContain(name)
    expect(banner.text()).not.toMatch(/10\.1\.0\./)
    // 送出對話框已收起，沒有任何一台被改動的暗示
    expect(wrapper.find('.dialog-stub').exists()).toBe(false)
  })

  it('按「重新整理」重新載入目標、選取歸零、橫幅消失', async () => {
    const wrapper = await mountBatchPage()
    selectAll(wrapper)
    createBatchMock.mockRejectedValueOnce(unavailableError(3))
    wrapper.vm.openBatch()
    await flushPromises()
    await wrapper.find('[data-test="submit-batch"]').trigger('click')
    await flushPromises()
    const before = targetsMock.mock.calls.length

    await wrapper.find('[data-test="unavailable-refresh"]').trigger('click')
    await flushPromises()

    expect(targetsMock.mock.calls.length).toBe(before + 1)
    expect(targetsMock).toHaveBeenLastCalledWith('ops')
    expect(wrapper.vm.selected).toEqual([])
    expect(wrapper.find('[data-test="unavailable-banner"]').exists()).toBe(false)
  })

  it('其他錯誤不顯示橫幅', async () => {
    const wrapper = await mountBatchPage()
    selectAll(wrapper)
    createBatchMock.mockRejectedValueOnce({ response: { status: 500, data: { code: 'INTERNAL_ERROR' } } })
    vi.spyOn(console, 'error').mockImplementation(() => {})
    wrapper.vm.openBatch()
    await flushPromises()
    await wrapper.find('[data-test="submit-batch"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-test="unavailable-banner"]').exists()).toBe(false)
  })
})

describe('批次改密頁：整批同一組的歸屬欄位', () => {
  async function openDialog(wrapper, mode) {
    selectAll(wrapper)
    wrapper.vm.openBatch()
    await flushPromises()
    wrapper.vm.form.password_mode = mode
    await flushPromises()
  }

  it('每台各自隨機：不顯示歸屬、不請求節點、本文不含歸屬欄', async () => {
    const wrapper = await mountBatchPage()
    await openDialog(wrapper, 'per_target')
    expect(wrapper.find('[data-test="ownership-row"]').exists()).toBe(false)
    expect(groupsMock).not.toHaveBeenCalled()

    await wrapper.find('[data-test="submit-batch"]').trigger('click')
    await flushPromises()
    const body = createBatchMock.mock.calls[0][0]
    expect(body.password_mode).toBe('per_target')
    expect(body).not.toHaveProperty('shared_credential_ownership')
  })

  it('整批同一組（範圍化）：選項請求帶 purpose=credential_create，本文帶所選節點', async () => {
    groupsMock.mockResolvedValue({
      selectable_all: false,
      data: [
        { id: 5, name: 'in-scope', path: '/in-scope', selectable: true },
        { id: 1, name: 'ancestor', path: '/ancestor', selectable: false },
      ],
    })
    const wrapper = await mountBatchPage()
    await openDialog(wrapper, 'shared')

    expect(groupsMock).toHaveBeenCalledWith({ purpose: 'credential_create' })
    expect(wrapper.find('[data-test="ownership-row"]').exists()).toBe(true)
    // 範圍化主體沒有「全域」：未選到可選節點前不能送出
    expect(wrapper.find('[data-test="submit-batch"]').attributes('disabled')).toBeDefined()

    wrapper.vm.form.shared_credential_ownership = { kind: 'node', node_id: 5 }
    await flushPromises()
    expect(wrapper.find('[data-test="submit-batch"]').attributes('disabled')).toBeUndefined()

    await wrapper.find('[data-test="submit-batch"]').trigger('click')
    await flushPromises()
    const body = createBatchMock.mock.calls[0][0]
    expect(body.password_mode).toBe('shared')
    expect(body.shared_credential_ownership).toEqual({ kind: 'node', node_id: 5 })
  })

  it('整批同一組（全域）：預設全域，本文帶 kind=global', async () => {
    groupsMock.mockResolvedValue({ data: [{ id: 5, name: 'n', path: '/n' }] })
    const wrapper = await mountBatchPage()
    await openDialog(wrapper, 'shared')
    await wrapper.find('[data-test="submit-batch"]').trigger('click')
    await flushPromises()
    expect(createBatchMock.mock.calls[0][0].shared_credential_ownership).toEqual({ kind: 'global' })
  })

  it.each(Object.keys(LOCALES))('%s：全域歸屬不出現所選節點提示，選節點才出現', async (locale) => {
    setLanguage(locale)
    groupsMock.mockResolvedValue({
      data: [{ id: 5, name: 'n', path: '/n', selectable: true }],
    })
    const wrapper = await mountBatchPage()
    await openDialog(wrapper, 'shared')
    const nodeHint = lookup(LOCALES[locale], 'changeSecretBatches.ownershipHint')
    const globalHint = lookup(LOCALES[locale], 'credentials.ownership.globalExplain')

    expect(wrapper.vm.form.shared_credential_ownership).toMatchObject({ kind: 'global' })
    expect(wrapper.find('[data-test="ownership-hint"]').text()).toBe(globalHint)
    expect(wrapper.find('[data-test="ownership-row"]').text()).not.toContain(nodeHint)

    wrapper.vm.form.shared_credential_ownership = { kind: 'node', node_id: 5 }
    await flushPromises()
    expect(wrapper.find('[data-test="ownership-hint"]').text()).toBe(nodeHint)
    expect(wrapper.find('[data-test="ownership-row"]').text()).not.toContain(globalHint)
  })
})

// ---------------------------------------------------------------- 7.2 批次新增錯誤清單

describe('批次新增：兩個匯入專屬問題文字', () => {
  const ERRORS = {
    node: { field: 'nodes', code: 'NOTFOUND_ASSET_IMPORT_NODE_PATH', params: { path: '/某處' } },
    cred: { field: 'credential_id', code: 'NOTFOUND_CREDENTIAL', params: {} },
    other: { field: 'host', code: 'VALIDATION_ASSET_IMPORT_ROWS_INVALID', params: {} },
  }

  function report() {
    const row = newRow('ssh')
    row.name = 'import-1'
    const rows = ref([row])
    const check = ref({
      keys: [row.key],
      preview: { rows: [{}] },
      errors: { [row.key]: [ERRORS.node, ERRORS.cred, ERRORS.other] },
    })
    const lines = ref({ [row.key]: 2 })
    return { row, ...useBulkErrorReport({ rows, check, lines }) }
  }

  const PROBLEM_TEXT = {
    'zh-TW': ['節點不存在，或你無法使用', '共用憑證不存在，或你無法使用'],
    'en-US': ['The node does not exist, or you cannot use it', 'The shared credential does not exist, or you cannot use it'],
    'ja-JP': ['ノードが存在しないか、利用できません', '共用認証情報が存在しないか、利用できません'],
  }

  it.each(Object.keys(LOCALES))('%s：錯誤清單的問題欄', (locale) => {
    setLanguage(locale)
    const { errorItems } = report()
    const [nodeText, credText] = PROBLEM_TEXT[locale]
    expect(errorItems.value[0].problem).toBe(nodeText)
    expect(errorItems.value[1].problem).toBe(credText)
    // 其他碼仍走通用錯誤譯文，不被匯入專屬文字吃掉
    expect(errorItems.value[2].problem).toBe(
      resolveApiError({ code: ERRORS.other.code, params: ERRORS.other.params })
    )
  })

  it('zh-TW 文字逐字同核可稿', () => {
    expect(PROBLEM_TEXT['zh-TW']).toEqual(['節點不存在，或你無法使用', '共用憑證不存在，或你無法使用'])
    expect(zhTW.assets.bulk.colProblem).toBe('問題')
  })

  it('下載 CSV 同文字', async () => {
    let blob = null
    const original = window.URL.createObjectURL
    window.URL.createObjectURL = (b) => {
      blob = b
      return 'blob:test'
    }
    window.URL.revokeObjectURL = () => {}
    try {
      const { downloadErrors } = report()
      downloadErrors()
    } finally {
      window.URL.createObjectURL = original
    }
    const csv = await blob.text()
    expect(csv).toContain('節點不存在，或你無法使用')
    expect(csv).toContain('共用憑證不存在，或你無法使用')
    // 伺服器帶在 params 的路徑不進 CSV
    expect(csv).not.toContain(ERRORS.node.params.path)
  })

  it('儲存格提示同文字', () => {
    const tableStub = {
      name: 'ElTable',
      props: ['data'],
      provide() {
        return { stubRows: computed(() => this.data || []) }
      },
      template: '<div class="table-stub"><slot /></div>',
    }
    const columnStub = {
      name: 'ElTableColumn',
      props: ['label', 'prop'],
      inject: { stubRows: { default: null } },
      computed: {
        rows() {
          const r = this.stubRows
          return Array.isArray(r) ? r : r?.value || []
        },
      },
      template:
        '<div class="col-stub"><div v-for="(row, i) in rows" :key="i"><slot :row="row" :column="{}" :$index="i" /></div></div>',
    }
    const row = newRow('ssh')
    row.name = 'import-1'
    row.host = '10.0.0.9'
    const wrapper = mount(BulkAssetTable, {
      props: {
        rows: [row],
        errors: { [row.key]: [ERRORS.node, ERRORS.cred] },
      },
      global: {
        plugins: [ElementPlus],
        stubs: { ElTable: tableStub, ElTableColumn: columnStub, 'el-tree-select': { template: '<div />' } },
      },
    })
    const text = wrapper.text()
    expect(text).toContain('節點不存在，或你無法使用')
    expect(text).toContain('共用憑證不存在，或你無法使用')
  })
})

// ---------------------------------------------------------------- 7.3 改密計畫頁

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
  target_kind: 'credential',
  target_credential_id: 77,
  target_credential_name: 'shared-cred-77',
  authorization_state: '',
  ...overrides,
})

async function mountPlans(plans) {
  listPlansMock.mockResolvedValue({ data: plans })
  const wrapper = mount(ChangeSecretPlans, {
    global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub } },
  })
  await flushPromises()
  return wrapper
}

describe('改密計畫頁：上界暫停與重新確認', () => {
  beforeEach(() => {
    updatePlanMock.mockResolvedValue({ data: {} })
    impactMock.mockResolvedValue({
      required: true,
      confirmation_id: 'conf-1',
      in_scope_count: 2,
      out_of_scope_asset_count: 9,
    })
  })

  it.each(Object.keys(LOCALES))('%s：needs_reconfirmation 顯示原因文字與重新確認入口', async (locale) => {
    setLanguage(locale)
    const wrapper = await mountPlans([planFixture({ authorization_state: 'needs_reconfirmation' })])
    const reason = wrapper.find('[data-test="plan-reconfirm-reason-1"]')
    expect(reason.exists()).toBe(true)
    expect(reason.text()).toContain(
      lookup(LOCALES[locale], 'changeSecretPlans.reason.CHANGE_SECRET_SCOPE_BOUND_EXCEEDED')
    )
    expect(wrapper.find('[data-test="plan-reconfirm-1"]').exists()).toBe(true)
    // 與「升級後無法確認發起者」的橫幅分開
    expect(wrapper.find('[data-test="paused-plans-banner"]').exists()).toBe(false)
  })

  it.each(Object.keys(LOCALES))('%s：needs_reauthorization 的呈現與現行相同：只有橫幅，沒有重新確認元素', async (locale) => {
    setLanguage(locale)
    const wrapper = await mountPlans([planFixture({ authorization_state: 'needs_reauthorization' })])
    const banner = wrapper.find('[data-test="paused-plans-banner"]')
    expect(banner.exists()).toBe(true)
    expect(banner.find('.el-alert__title').text()).toBe(
      fill(lookup(LOCALES[locale], 'changeSecretPlans.reauthorize.banner'), { count: 1 })
    )
    expect(banner.find('[data-test="reauthorize-plans"]').text()).toBe(
      lookup(LOCALES[locale], 'changeSecretPlans.reauthorize.button')
    )
    expect(wrapper.find('[data-test="plan-reconfirm-reason-1"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="plan-reconfirm-1"]').exists()).toBe(false)
  })

  it('一般計畫沒有重新確認入口', async () => {
    const wrapper = await mountPlans([planFixture()])
    expect(wrapper.find('[data-test="plan-reconfirm-1"]').exists()).toBe(false)
  })

  it('確認對話框只顯示台數、不含資產名，勾選後送出本文帶確認版本', async () => {
    const wrapper = await mountPlans([
      planFixture({ authorization_state: 'needs_reconfirmation', accounts: '["ops-admin"]' }),
    ])
    await wrapper.find('[data-test="plan-reconfirm-1"]').trigger('click')
    await flushPromises()

    expect(impactMock).toHaveBeenCalledWith(77, 'rotate')
    const body = wrapper.find('[data-test="reconfirm-body"]')
    expect(body.text()).toBe(fill(zhTW.changeSecretPlans.reconfirmBody, { count: 9 }))
    expect(wrapper.findAll('.dialog-stub')).toHaveLength(1)
    const dialog = wrapper.find('.dialog-stub')
    expect(dialog.find('h3').text()).toBe(zhTW.changeSecretPlans.reconfirmTitle)
    expect(dialog.find('[data-test="reconfirm-ack"]').text()).toBe(
      fill(zhTW.changeSecretPlans.reconfirmAck, { count: 9 })
    )
    // 範圍內台數（2）與任何資產、帳號、憑證名稱都不進對話框
    for (const name of ['plan-host', '10.0.0.1', 'ops-admin', 'shared-cred-77']) {
      expect(dialog.text()).not.toContain(name)
    }
    expect(updatePlanMock).not.toHaveBeenCalled()
    // 未勾選知情前不能送出
    expect(wrapper.find('[data-test="reconfirm-submit"]').attributes('disabled')).toBeDefined()

    await wrapper.find('[data-test="reconfirm-ack"] input').setValue(true)
    await wrapper.find('[data-test="reconfirm-submit"]').trigger('click')
    await flushPromises()

    expect(updatePlanMock).toHaveBeenCalledTimes(1)
    const [id, payload] = updatePlanMock.mock.calls[0]
    expect(id).toBe(1)
    expect(payload.impact_confirmation_id).toBe('conf-1')
    expect(payload.target_kind).toBe('credential')
    expect(payload.target_credential_id).toBe(77)
    expect(payload.asset_ids).toEqual([1])
  })

  it('重新確認的重存：非預設設定原樣帶回，只多一個確認欄', async () => {
    const wrapper = await mountPlans([
      planFixture({
        authorization_state: 'needs_reconfirmation',
        enabled: false,
        asset_ids: '[1,2]',
        accounts: '["ops-admin"]',
        key_strategy: 'replace',
        password_length: 24,
        password_include_symbol: false,
        password_exclude_ambiguous: false,
        cron: '30 4 * * 1',
        max_age_days: 45,
      }),
    ])
    await wrapper.find('[data-test="plan-reconfirm-1"]').trigger('click')
    await flushPromises()
    await wrapper.find('[data-test="reconfirm-ack"] input').setValue(true)
    await wrapper.find('[data-test="reconfirm-submit"]').trigger('click')
    await flushPromises()

    expect(updatePlanMock).toHaveBeenCalledTimes(1)
    expect(updatePlanMock.mock.calls[0][1]).toEqual({
      name: 'weekly',
      asset_ids: [1, 2],
      accounts: ['ops-admin'],
      secret_type: 'password',
      key_strategy: 'replace',
      password_length: 24,
      password_include_symbol: false,
      password_exclude_ambiguous: false,
      cron: '30 4 * * 1',
      max_age_days: 45,
      enabled: false,
      target_kind: 'credential',
      target_credential_id: 77,
      impact_confirmation_id: 'conf-1',
    })
  })

  it('範圍外集合在期間擴大（409）：以新台數重開確認，不另跳錯誤', async () => {
    const wrapper = await mountPlans([planFixture({ authorization_state: 'needs_reconfirmation' })])
    await wrapper.find('[data-test="plan-reconfirm-1"]').trigger('click')
    await flushPromises()
    await wrapper.find('[data-test="reconfirm-ack"] input').setValue(true)

    updatePlanMock.mockRejectedValueOnce({
      response: { status: 409, data: { code: 'RULE_CREDENTIAL_IMPACT_CONFIRMATION_REQUIRED', params: { count: 10 } } },
    })
    impactMock.mockResolvedValueOnce({
      required: true,
      confirmation_id: 'conf-2',
      in_scope_count: 2,
      out_of_scope_asset_count: 10,
    })
    await wrapper.find('[data-test="reconfirm-submit"]').trigger('click')
    await flushPromises()

    expect(wrapper.find('[data-test="reconfirm-body"]').text()).toContain('10')
    // 重開後需重新勾選
    expect(wrapper.find('[data-test="reconfirm-submit"]').attributes('disabled')).toBeDefined()
  })

  it('三語鍵齊備', () => {
    const keys = [
      'changeSecretPlans.reconfirmTitle',
      'changeSecretPlans.reconfirmBody',
      'changeSecretPlans.reconfirmButton',
      'changeSecretPlans.reconfirmAck',
      'changeSecretPlans.reconfirmSubmit',
      'changeSecretPlans.reconfirmDone',
      'changeSecretPlans.reconfirmTag',
      'changeSecretPlans.reason.CHANGE_SECRET_SCOPE_BOUND_EXCEEDED',
      'changeSecretBatches.unavailableBanner',
      'changeSecretBatches.ownershipHint',
    ]
    for (const [locale, messages] of Object.entries(LOCALES)) {
      for (const key of keys) expect(lookup(messages, key), `${locale} ${key}`).toBeTruthy()
    }
    expect(i18n.global.te('changeSecretPlans.reconfirmTitle')).toBe(true)
  })
})

describe('改密計畫頁：一般儲存的範圍外影響確認', () => {
  const baseBody = {
    name: 'weekly',
    asset_ids: [1],
    accounts: ['@ALL'],
    secret_type: 'password',
    key_strategy: 'append_replace',
    password_length: 16,
    password_include_symbol: true,
    password_exclude_ambiguous: true,
    cron: '0 3 * * 0',
    max_age_days: 0,
    enabled: true,
  }

  beforeEach(() => {
    updatePlanMock.mockReset()
    createPlanMock.mockReset()
    impactMock.mockReset()
    updatePlanMock.mockResolvedValue({ data: {} })
    createPlanMock.mockResolvedValue({ data: {} })
  })

  const requiredNine = {
    required: true,
    confirmation_id: 'conf-9',
    in_scope_count: 2,
    out_of_scope_asset_count: 9,
  }

  const conflict = () =>
    Object.assign(new Error('conflict'), {
      response: { status: 409, data: { code: 'RULE_CREDENTIAL_IMPACT_CONFIRMATION_REQUIRED' } },
    })
  const credentialBody = { ...baseBody, target_kind: 'credential', target_credential_id: 77 }

  it('憑證目標被要求確認：先送本文，只顯示台數的一般文案，確認後帶確認版本重送', async () => {
    impactMock.mockResolvedValue(requiredNine)
    updatePlanMock.mockRejectedValueOnce(conflict())
    const wrapper = await mountPlans([planFixture({ accounts: '["@ALL"]' })])
    wrapper.vm.openEdit(wrapper.vm.plans[0])
    await flushPromises()
    await wrapper.vm.submit()
    await flushPromises()

    expect(updatePlanMock).toHaveBeenCalledTimes(1)
    expect(updatePlanMock.mock.calls[0][1]).toEqual(credentialBody)
    expect(impactMock).toHaveBeenCalledTimes(1)
    expect(impactMock).toHaveBeenCalledWith(77, 'rotate')
    // 一般編輯不使用含「恢復執行」語意的段落
    expect(wrapper.find('[data-test="reconfirm-body"]').exists()).toBe(false)
    const ack = wrapper.find('[data-test="reconfirm-ack"]')
    expect(ack.text()).toBe(fill(zhTW.credentials.impact.ackRotate, { count: 9 }))
    const dialog = ack.element.closest('.dialog-stub')
    expect(dialog.querySelector('h3').textContent).toBe(zhTW.credentials.impact.title)
    for (const name of ['plan-host', '10.0.0.1', 'shared-cred-77', '恢復執行']) {
      expect(dialog.textContent).not.toContain(name)
    }
    expect(wrapper.vm.dialogVisible).toBe(true)

    await ack.find('input').setValue(true)
    await wrapper.find('[data-test="reconfirm-submit"]').trigger('click')
    await flushPromises()

    expect(updatePlanMock).toHaveBeenCalledTimes(2)
    expect(updatePlanMock.mock.calls[1][0]).toBe(1)
    expect(updatePlanMock.mock.calls[1][1]).toEqual({
      ...credentialBody,
      impact_confirmation_id: 'conf-9',
    })
    expect(wrapper.vm.dialogVisible).toBe(false)
  })

  it('無輪替能力、後端直接接受：不呼叫確認端點，儲存成功', async () => {
    impactMock.mockRejectedValue(new Error('403'))
    const wrapper = await mountPlans([planFixture()])
    wrapper.vm.openEdit(wrapper.vm.plans[0])
    await flushPromises()
    await wrapper.vm.submit()
    await flushPromises()

    expect(impactMock).not.toHaveBeenCalled()
    expect(wrapper.find('[data-test="reconfirm-ack"]').exists()).toBe(false)
    expect(updatePlanMock).toHaveBeenCalledTimes(1)
    expect(updatePlanMock.mock.calls[0][1]).toEqual(credentialBody)
    expect(wrapper.vm.dialogVisible).toBe(false)
  })

  it('被要求確認但重查已不需確認：重送一次即成功，不開對話框', async () => {
    impactMock.mockResolvedValue({ required: false, in_scope_count: 11, out_of_scope_asset_count: 0 })
    updatePlanMock.mockRejectedValueOnce(conflict())
    const wrapper = await mountPlans([planFixture()])
    wrapper.vm.openEdit(wrapper.vm.plans[0])
    await flushPromises()
    await wrapper.vm.submit()
    await flushPromises()

    expect(impactMock).toHaveBeenCalledTimes(1)
    expect(updatePlanMock).toHaveBeenCalledTimes(2)
    expect(updatePlanMock.mock.calls[1][1]).toEqual(credentialBody)
    expect(wrapper.find('[data-test="reconfirm-ack"]').exists()).toBe(false)
    expect(wrapper.vm.dialogVisible).toBe(false)
  })

  it('被要求確認、重查不需確認、重送仍失敗：畫面顯示在地化錯誤提示', async () => {
    impactMock.mockResolvedValue({ required: false, in_scope_count: 11, out_of_scope_asset_count: 0 })
    updatePlanMock.mockRejectedValueOnce(conflict()).mockRejectedValueOnce(conflict())
    const errorSpy = vi.spyOn(ElMessage, 'error').mockImplementation(() => {})
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const wrapper = await mountPlans([planFixture()])
      wrapper.vm.openEdit(wrapper.vm.plans[0])
      await flushPromises()
      await wrapper.vm.submit()
      await flushPromises()

      expect(updatePlanMock).toHaveBeenCalledTimes(2)
      expect(errorSpy).toHaveBeenCalledTimes(1)
      expect(String(errorSpy.mock.calls[0][0])).not.toBe('')
      expect(wrapper.vm.dialogVisible).toBe(true)
    } finally {
      errorSpy.mockRestore()
      consoleSpy.mockRestore()
    }
  })

  it('不需確認時的一般儲存：不出現對話框，本文不帶確認欄', async () => {
    const wrapper = await mountPlans([planFixture()])
    wrapper.vm.openEdit(wrapper.vm.plans[0])
    await flushPromises()
    await wrapper.vm.submit()
    await flushPromises()

    expect(wrapper.find('[data-test="reconfirm-body"]').exists()).toBe(false)
    expect(updatePlanMock).toHaveBeenCalledTimes(1)
    expect(updatePlanMock.mock.calls[0][1]).toEqual(credentialBody)
    expect(wrapper.vm.dialogVisible).toBe(false)
  })

  it('取消確認：不帶確認重送，編輯表單仍開著', async () => {
    impactMock.mockResolvedValue(requiredNine)
    updatePlanMock.mockRejectedValueOnce(conflict())
    const wrapper = await mountPlans([planFixture()])
    wrapper.vm.openEdit(wrapper.vm.plans[0])
    await flushPromises()
    await wrapper.vm.submit()
    await flushPromises()
    expect(wrapper.find('[data-test="reconfirm-ack"]').exists()).toBe(true)

    const cancel = wrapper
      .find('[data-test="reconfirm-submit"]')
      .element.parentElement.querySelector('button:not([data-test])')
    cancel.click()
    await flushPromises()

    expect(wrapper.find('[data-test="reconfirm-ack"]').exists()).toBe(false)
    expect(updatePlanMock).toHaveBeenCalledTimes(1)
    expect(createPlanMock).not.toHaveBeenCalled()
    expect(wrapper.vm.dialogVisible).toBe(true)
  })

  it('編輯帳號目標計畫：不呼叫確認端點，本文不帶目標欄與確認欄', async () => {
    const wrapper = await mountPlans([planFixture({ target_kind: 'account', target_credential_id: null })])
    wrapper.vm.openEdit(wrapper.vm.plans[0])
    await flushPromises()
    await wrapper.vm.submit()
    await flushPromises()
    expect(impactMock).not.toHaveBeenCalled()
    expect(updatePlanMock).toHaveBeenCalledTimes(1)
    expect(updatePlanMock.mock.calls[0][1]).toEqual(baseBody)
  })

  it('新增帳號目標計畫：不呼叫確認端點，本文不帶目標欄與確認欄', async () => {
    const wrapper = await mountPlans([])
    wrapper.vm.openCreate()
    await flushPromises()
    wrapper.vm.form.name = 'fresh'
    wrapper.vm.form.asset_ids = [1]
    wrapper.vm.form.cron = '0 3 * * 0'
    await wrapper.vm.submit()
    await flushPromises()
    expect(impactMock).not.toHaveBeenCalled()
    expect(createPlanMock).toHaveBeenCalledTimes(1)
    expect(createPlanMock.mock.calls[0][0]).toEqual({ ...baseBody, name: 'fresh' })
  })

  it('編輯既有憑證計畫：表單保留目標欄，未經確認流程的本文也不丟失目標', async () => {
    const wrapper = await mountPlans([planFixture({ max_age_days: 45, cron: '30 4 * * 1' })])
    wrapper.vm.openEdit(wrapper.vm.plans[0])
    expect(wrapper.vm.form.target_kind).toBe('credential')
    expect(wrapper.vm.form.target_credential_id).toBe(77)
    expect(wrapper.vm.buildPayload()).toEqual({
      ...baseBody,
      cron: '30 4 * * 1',
      max_age_days: 45,
      target_kind: 'credential',
      target_credential_id: 77,
    })
  })
})
