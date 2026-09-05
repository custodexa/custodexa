import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import AccountBatchRotation from '../AccountBatchRotation.vue'
import { ROTATION_BUCKETS } from '@/constants/rotationEvidence'

// 帳號批次改密的處置看板。
//
// 斷言重心在四件會靜默出錯的事：
//  1. 目標分欄與卡片數——少一張卡片就是少改一台，而畫面上看不出來；
//  2. 整批同一組的風險提示——它是這個模式與另一個模式唯一的差別提示；
//  3. 送出的集合與模式必須就是畫面上勾的那一份，且執行結果三種狀態各自可辨識；
//  4. 不可改密的目標仍列出但不可勾選（列出是為了回答「這台為什麼不在名單上」）。

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

const usernamesMock = vi.fn()
const targetsMock = vi.fn()
const createMock = vi.fn()
const listMock = vi.fn()
const getMock = vi.fn()

vi.mock('@/api/changeSecretBatches', () => ({
  getChangeSecretBatchUsernames: (...a) => usernamesMock(...a),
  getChangeSecretBatchTargets: (...a) => targetsMock(...a),
  createChangeSecretBatch: (...a) => createMock(...a),
  getChangeSecretBatches: (...a) => listMock(...a),
  getChangeSecretBatch: (...a) => getMock(...a),
}))

// 對話框預設 teleport 到 body，掛載樹上找不到；以就地渲染的替身取代
const dialogStub = {
  props: ['modelValue'],
  template:
    '<div v-if="modelValue" class="dialog-stub"><slot /><slot name="footer" /></div>',
}

const targetFixture = (overrides = {}) => ({
  account_id: 1,
  asset_id: 11,
  asset_name: 'srv-1',
  asset_address: '10.0.0.1',
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
  ...overrides,
})

// 六個目標散落六個狀態桶，其中兩個不可改密（候選待驗證、通道未設定）
const targetsFixture = () => [
  targetFixture({ account_id: 1, asset_id: 11, asset_name: 'srv-1', bucket: 'overdue', remaining_days_a: -5 }),
  targetFixture({
    account_id: 2, asset_id: 12, asset_name: 'srv-2', bucket: 'due_soon',
    remaining_days_a: 7, shared_credential: true,
  }),
  targetFixture({ account_id: 3, asset_id: 13, asset_name: 'srv-3', bucket: 'no_record' }),
  targetFixture({
    account_id: 4, asset_id: 14, asset_name: 'srv-4', bucket: 'compliant',
    remaining_days_a: 40, privileged: true,
  }),
  targetFixture({
    account_id: 5, asset_id: 15, asset_name: 'srv-5', bucket: 'unverified',
    candidate_state: 'applied', ineligible_reason: 'CHANGE_SECRET_CANDIDATE_PENDING',
  }),
  targetFixture({
    account_id: 6, asset_id: 16, asset_name: 'srv-6', bucket: 'no_policy',
    protocol: 'rdp', rotation_channel: 'none',
    ineligible_reason: 'CHANGE_SECRET_CHANNEL_NOT_CONFIGURED',
  }),
]

const batchFixture = (overrides = {}) => ({
  id: 7,
  username: 'ops',
  password_mode: 'per_target',
  password_length: 16,
  password_include_symbol: true,
  password_exclude_ambiguous: true,
  target_count: 3,
  success_count: 0,
  failed_count: 0,
  unverified_count: 0,
  skipped_count: 0,
  status: 'running',
  requested_by: 1,
  requested_by_name: 'admin',
  started_at: '2026-09-06T02:00:00Z',
  finished_at: null,
  created_at: '2026-09-06T02:00:00Z',
  ...overrides,
})

const recordsFixture = () => [
  {
    id: 101, plan_id: 0, batch_id: 7, asset_id: 11, account_id: 1,
    account_username: 'ops', secret_type: 'password', status: 'success',
    error: '', executed_at: '2026-09-06T02:00:05Z',
  },
  {
    id: 102, plan_id: 0, batch_id: 7, asset_id: 12, account_id: 2,
    account_username: 'ops', secret_type: 'password', status: 'failed',
    error: 'CHANGE_SECRET_REMOTE_REJECTED', executed_at: '2026-09-06T02:00:06Z',
  },
  {
    id: 103, plan_id: 0, batch_id: 7, asset_id: 13, account_id: 3,
    account_username: 'ops', secret_type: 'password', status: 'unverified',
    error: 'CHANGE_SECRET_REMOTE_STATE_UNKNOWN', executed_at: '2026-09-06T02:00:07Z',
  },
]

async function mountPage() {
  const wrapper = mount(AccountBatchRotation, {
    global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub } },
  })
  await flushPromises()
  return wrapper
}

async function mountWithTargets() {
  const wrapper = await mountPage()
  await wrapper.vm.selectUsername('ops')
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  vi.clearAllMocks()
  usernamesMock.mockResolvedValue({ data: [{ username: 'ops', asset_count: 6 }], total: 1 })
  targetsMock.mockResolvedValue({ data: targetsFixture(), total: 6 })
  listMock.mockResolvedValue({ data: [], total: 0 })
  createMock.mockResolvedValue({ data: batchFixture() })
  getMock.mockResolvedValue({ data: { batch: batchFixture(), records: [] } })
})

describe('選定帳號名後的目標看板', () => {
  it('依狀態桶分欄，卡片數等於目標數', async () => {
    const wrapper = await mountWithTargets()
    expect(targetsMock).toHaveBeenCalledWith('ops')

    // 欄數＝狀態桶值域；桶少一個就是有一批目標無處可去
    const columns = wrapper.findAll('.board-column')
    expect(columns).toHaveLength(ROTATION_BUCKETS.length)

    const cards = wrapper.findAll('[data-test^="target-card-"]')
    expect(cards).toHaveLength(targetsFixture().length)

    for (const bucket of ROTATION_BUCKETS) {
      const column = wrapper.find(`[data-test="bucket-column-${bucket}"]`)
      expect(column.exists(), bucket).toBe(true)
      expect(column.find(`[data-test="bucket-count-${bucket}"]`).text(), bucket).toBe('1')
    }

    // 逾期那一欄裝的就是逾期那一台，卡片帶資產名與帳號名
    const overdue = wrapper.find('[data-test="bucket-column-overdue"]')
    expect(overdue.find('[data-test="target-card-1"]').exists()).toBe(true)
    expect(overdue.text()).toContain('srv-1')
    expect(overdue.text()).toContain('ops')

    // 共用與特權標記沿輪替證據的同一組文案
    expect(wrapper.find('[data-test="target-card-2"]').text()).toContain('共用憑證')
    expect(wrapper.find('[data-test="target-card-4"]').text()).toContain('特權')
  })
})

describe('密碼模式的風險提示', () => {
  it('整批同一組顯示風險提示，每台各自隨機不顯示', async () => {
    const wrapper = await mountWithTargets()
    wrapper.vm.toggleTarget(targetsFixture()[0])
    wrapper.vm.openBatch()
    await flushPromises()

    // 預設是每台各自隨機：整批同一組要人明確選
    expect(wrapper.vm.form.password_mode).toBe('per_target')
    expect(wrapper.find('[data-test="shared-risk"]').exists()).toBe(false)

    wrapper.vm.form.password_mode = 'shared'
    await flushPromises()
    const risk = wrapper.find('[data-test="shared-risk"]')
    expect(risk.exists()).toBe(true)
    expect(risk.text()).toContain('任一台外洩即等同全部外洩')
  })
})

describe('送出與執行結果', () => {
  it('payload 帶所勾選的帳號與密碼模式，輪詢至完成後三種狀態各自呈現', async () => {
    const wrapper = await mountWithTargets()
    const targets = targetsFixture()
    wrapper.vm.toggleTarget(targets[0])
    wrapper.vm.toggleTarget(targets[1])
    wrapper.vm.openBatch()
    await flushPromises()
    wrapper.vm.form.password_mode = 'shared'
    await flushPromises()

    createMock.mockResolvedValue({ data: batchFixture({ password_mode: 'shared' }) })
    getMock.mockResolvedValue({
      data: { batch: batchFixture({ password_mode: 'shared' }), records: [recordsFixture()[0]] },
    })
    await wrapper.vm.submit()
    await flushPromises()

    expect(createMock).toHaveBeenCalledTimes(1)
    const payload = createMock.mock.calls[0][0]
    expect(payload.username).toBe('ops')
    expect(payload.account_ids).toEqual([1, 2])
    expect(payload.password_mode).toBe('shared')
    expect(payload.password_length).toBe(16)

    // 尚未完成：狀態為執行中，且已排下一次查詢
    expect(wrapper.find('[data-test="batch-status"]').text()).toBe('執行中')
    expect(wrapper.vm.polling).toBe(true)

    // 下一次查詢回到完成：輪詢停止，三種狀態各自呈現
    getMock.mockResolvedValue({
      data: {
        batch: batchFixture({
          password_mode: 'shared', status: 'completed',
          success_count: 1, failed_count: 1, unverified_count: 1,
          finished_at: '2026-09-06T02:00:08Z',
        }),
        records: recordsFixture(),
      },
    })
    await wrapper.vm.pollBatch(7, 1)
    await flushPromises()

    expect(wrapper.vm.polling).toBe(false)
    expect(wrapper.find('[data-test="batch-status"]').text()).toBe('已完成')

    const statuses = [101, 102, 103].map((id) =>
      wrapper.find(`[data-test="record-status-${id}"]`).text()
    )
    expect(new Set(statuses).size).toBe(3)
    expect(statuses[0]).toBe('成功')
    expect(statuses[1]).toBe('失敗')
    expect(statuses[2]).toContain('未驗證')

    // 失敗原因走機器碼對照表，畫面上不出現機器碼本身
    const result = wrapper.find('[data-test="batch-result"]')
    expect(result.text()).not.toContain('CHANGE_SECRET_REMOTE_REJECTED')
    expect(result.text()).toContain('srv-1')
    expect(result.text()).toContain('整批同一組')
  })
})

describe('不可改密的目標', () => {
  it('仍列出但核取方塊停用，且原因看得到', async () => {
    const wrapper = await mountWithTargets()

    const pending = wrapper.find('[data-test="target-check-5"] input')
    expect(pending.element.disabled).toBe(true)
    const noChannel = wrapper.find('[data-test="target-check-6"] input')
    expect(noChannel.element.disabled).toBe(true)
    const rotatable = wrapper.find('[data-test="target-check-1"] input')
    expect(rotatable.element.disabled).toBe(false)

    expect(wrapper.find('[data-test="target-reason-6"]').text()).toContain('未設定改密通道')
    expect(wrapper.find('[data-test="target-rotate-6"]').exists()).toBe(false)

    // 桶內全選只選得到可改密者：把停用的卡片選進去只會在送出時被整筆拒絕
    wrapper.vm.toggleColumn({ bucket: 'unverified', items: [targetsFixture()[4]] })
    expect(wrapper.vm.selected).toEqual([])
    wrapper.vm.toggleTarget(targetsFixture()[4])
    expect(wrapper.vm.selected).toEqual([])
  })
})
