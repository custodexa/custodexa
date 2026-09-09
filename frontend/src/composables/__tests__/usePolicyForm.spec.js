import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { nextTick } from 'vue'

// 判定與套用語義都在後端：本檔釘的是前端有沒有照契約問、以及問到的答案有沒有
// 被原樣採用。前端自己算一份判定會與伺服器漂移，而分歧不會有任何一處報錯。

const messages = {
  info: vi.fn(),
  success: vi.fn(),
  warning: vi.fn(),
  error: vi.fn(),
}
vi.mock('element-plus', () => ({
  ElMessage: messages,
  ElMessageBox: { confirm: vi.fn(() => Promise.resolve()) },
}))

const getSecurityPolicies = vi.fn()
const updateSecurityPolicies = vi.fn()
const previewCompliance = vi.fn()
const previewApplyPolicies = vi.fn()
vi.mock('@/api/securityPolicies', () => ({
  getSecurityPolicies: (...a) => getSecurityPolicies(...a),
  updateSecurityPolicies: (...a) => updateSecurityPolicies(...a),
  previewCompliance: (...a) => previewCompliance(...a),
  previewApplyPolicies: (...a) => previewApplyPolicies(...a),
}))

vi.mock('@/i18n', () => ({
  t: (k) => k,
  currentLocale: () => 'zh-TW',
}))

const { usePolicyForm } = await import('../usePolicyForm')

const verdict = (key, group, result, over = {}) => ({
  key,
  group_code: group,
  clause_no: '8.3.6',
  result,
  reason: result === 'deviating' ? 'below_minimum' : 'meets_expectation',
  current: '8',
  expected: '12',
  comparator: 'min',
  ...over,
})

const POLICIES = [
  {
    key: 'password_min_length',
    type: 'int',
    value: '8',
    default: '12',
    label: '密碼最小長度',
    verdicts: [verdict('password_min_length', 'pci_dss_4_0_1', 'deviating')],
  },
  {
    key: 'lockout_max_attempts',
    type: 'int',
    value: '10',
    default: '10',
    zero_disables: true,
    label: '登入失敗鎖定次數上限',
    verdicts: [verdict('lockout_max_attempts', 'pci_dss_4_0_1', 'compliant')],
  },
  // 不屬本頁的鍵：套用範圍與儲存 payload 都不得碰它
  {
    key: 'transport_rdp_level',
    type: 'enum',
    value: 'off',
    enum_order: ['off', 'warn', 'strict'],
    label: 'RDP 傳輸強制等級',
    verdicts: [verdict('transport_rdp_level', 'pci_dss_4_0_1', 'deviating')],
  },
]

const SECTIONS = [
  {
    id: 'test',
    title: '測試區塊',
    hint: '',
    keys: ['password_min_length', 'lockout_max_attempts'],
  },
]

const listResponse = () => ({
  data: POLICIES.map((p) => ({ ...p, verdicts: p.verdicts.map((v) => ({ ...v })) })),
  groups: [
    { code: 'pci_dss_4_0_1', name: 'PCI DSS 4.0.1', enabled: true },
    { code: 'epayment_baseline', name: '支付基準組', enabled: true },
  ],
})

const loaded = async () => {
  const form = usePolicyForm(SECTIONS)
  await form.loadPolicies()
  return form
}

beforeEach(() => {
  vi.clearAllMocks()
  getSecurityPolicies.mockResolvedValue(listResponse())
  updateSecurityPolicies.mockResolvedValue(listResponse())
  previewCompliance.mockResolvedValue({ data: { draft: true, verdicts: [] } })
  previewApplyPolicies.mockResolvedValue({
    data: { mode: 'strictest', changes: [], conflicts: [], unchanged_count: 0, unmapped_count: 0 },
  })
})

describe('usePolicyForm — 判定來自後端', () => {
  it('列表回應的逐鍵判定與生效組直接採用', async () => {
    const form = await loaded()

    expect(form.verdictsByKey.value.password_min_length[0].result).toBe('deviating')
    expect(form.isDraftVerdicts.value).toBe(false)
    expect(form.groupNames.value).toEqual({
      pci_dss_4_0_1: 'PCI DSS 4.0.1',
      epayment_baseline: '支付基準組',
    })
  })

  it('沒有 verdicts 的舊回應不炸，判定為空', async () => {
    getSecurityPolicies.mockResolvedValue({ data: [{ ...POLICIES[0], verdicts: undefined }] })
    const form = await loaded()

    expect(form.verdictsByKey.value.password_min_length).toEqual([])
    expect(form.groups.value).toEqual([])
  })
})

describe('usePolicyForm — 草稿判定去抖', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  it('連續編輯只打一次草稿判定端點，且只送有變更的鍵', async () => {
    const form = await loaded()

    form.formValues.value.password_min_length = 13
    await nextTick()
    form.formValues.value.password_min_length = 14
    await nextTick()

    // 300ms 之內不打
    vi.advanceTimersByTime(299)
    expect(previewCompliance).not.toHaveBeenCalled()

    vi.advanceTimersByTime(1)
    await vi.waitFor(() => expect(previewCompliance).toHaveBeenCalledTimes(1))
    expect(previewCompliance).toHaveBeenCalledWith({ password_min_length: '14' })
  })

  it('草稿判定回來後改用草稿那一份並標示為草稿', async () => {
    previewCompliance.mockResolvedValue({
      data: {
        draft: true,
        verdicts: [verdict('password_min_length', 'pci_dss_4_0_1', 'compliant', { current: '14' })],
      },
    })
    const form = await loaded()

    form.formValues.value.password_min_length = 14
    await nextTick()
    vi.advanceTimersByTime(300)
    await vi.waitFor(() => expect(form.isDraftVerdicts.value).toBe(true))

    expect(form.verdictsByKey.value.password_min_length[0].result).toBe('compliant')
  })

  // 300 毫秒去抖擋得住「每敲一下打一次」，擋不住兩個已送出的請求倒序回來
  it('倒序回應不覆蓋：先送的晚回時丟棄，畫面留最後一次送出的結果', async () => {
    let resolveFirst
    const first = new Promise((resolve) => {
      resolveFirst = resolve
    })
    previewCompliance
      .mockReturnValueOnce(first)
      .mockResolvedValueOnce({
        data: {
          verdicts: [
            verdict('password_min_length', 'pci_dss_4_0_1', 'compliant', { current: '14' }),
          ],
        },
      })
    const form = await loaded()

    form.formValues.value.password_min_length = 12
    await nextTick()
    vi.advanceTimersByTime(300)
    await vi.waitFor(() => expect(previewCompliance).toHaveBeenCalledTimes(1))

    form.formValues.value.password_min_length = 14
    await nextTick()
    vi.advanceTimersByTime(300)
    await vi.waitFor(() => expect(previewCompliance).toHaveBeenCalledTimes(2))
    await vi.waitFor(() => expect(form.draftStatus.value).toBe('ready'))
    expect(form.verdictsByKey.value.password_min_length[0].current).toBe('14')

    // 12 那一次現在才回來：它說偏離，但畫面上的輸入值已經是 14
    resolveFirst({
      data: {
        verdicts: [
          verdict('password_min_length', 'pci_dss_4_0_1', 'deviating', { current: '12' }),
        ],
      },
    })
    await vi.waitFor(() => expect(previewCompliance).toHaveBeenCalledTimes(2))
    await Promise.resolve()

    expect(form.verdictsByKey.value.password_min_length[0].current).toBe('14')
    expect(form.draftStatus.value).toBe('ready')
  })

  it('草稿判定失敗時說判定失敗，不沿用上一份結果', async () => {
    previewCompliance.mockRejectedValueOnce(new Error('boom'))
    const form = await loaded()

    form.formValues.value.password_min_length = 14
    await nextTick()
    vi.advanceTimersByTime(300)
    await vi.waitFor(() => expect(form.draftStatus.value).toBe('failed'))

    // 舊判定不再被當成這一組輸入的答案
    expect(form.isDraftVerdicts.value).toBe(false)
  })

  it('還原使在途的草稿請求失效（回來的結果不再標成草稿）', async () => {
    let resolveDraft
    previewCompliance.mockReturnValueOnce(
      new Promise((resolve) => {
        resolveDraft = resolve
      })
    )
    const form = await loaded()

    form.formValues.value.password_min_length = 14
    await nextTick()
    vi.advanceTimersByTime(300)
    await vi.waitFor(() => expect(previewCompliance).toHaveBeenCalledTimes(1))

    form.resetForm()
    resolveDraft({
      data: {
        verdicts: [
          verdict('password_min_length', 'pci_dss_4_0_1', 'compliant', { current: '14' }),
        ],
      },
    })
    await Promise.resolve()
    await Promise.resolve()

    expect(form.isDraftVerdicts.value).toBe(false)
    expect(form.draftStatus.value).toBe('')
  })

  it('改回原值後不再標草稿（沒有草稿就用已儲存的判定）', async () => {
    const form = await loaded()

    form.formValues.value.password_min_length = 14
    await nextTick()
    vi.advanceTimersByTime(300)
    await vi.waitFor(() => expect(previewCompliance).toHaveBeenCalledTimes(1))

    form.formValues.value.password_min_length = 8
    await nextTick()
    vi.advanceTimersByTime(300)
    await vi.waitFor(() => expect(form.isDraftVerdicts.value).toBe(false))
    expect(previewCompliance).toHaveBeenCalledTimes(1)
  })
})

describe('usePolicyForm — 套用預覽', () => {
  it('預覽只送本頁鍵，並帶目前的草稿值', async () => {
    const form = await loaded()
    form.formValues.value.password_min_length = 13

    await form.previewApply('strictest')

    expect(previewApplyPolicies).toHaveBeenCalledWith({
      scope: ['password_min_length', 'lockout_max_attempts'],
      mode: 'strictest',
      group_code: '',
      draft: { password_min_length: '13' },
    })
    expect(form.previewVisible.value).toBe(true)
  })

  it('指定單組時帶組代號', async () => {
    const form = await loaded()

    await form.previewApply('group', 'pci_dss_4_0_1')

    expect(previewApplyPolicies.mock.calls[0][0]).toMatchObject({
      mode: 'group',
      group_code: 'pci_dss_4_0_1',
    })
  })

  it('確認後只填表單，不呼叫儲存', async () => {
    const form = await loaded()

    form.acceptPreview([
      { key: 'password_min_length', current: '8', proposed: '14', source_group: 'pci_dss_4_0_1' },
    ])

    expect(form.formValues.value.password_min_length).toBe(14)
    expect(form.isDirty.value).toBe(true)
    expect(updateSecurityPolicies).not.toHaveBeenCalled()
  })

  it('預覽端點失敗時不開對話框，也不動表單', async () => {
    previewApplyPolicies.mockRejectedValueOnce(new Error('boom'))
    const form = await loaded()

    await form.previewApply('strictest')

    expect(form.previewVisible.value).toBe(false)
    expect(form.formValues.value.password_min_length).toBe(8)
  })
})

describe('usePolicyForm — 儲存', () => {
  it('只送本頁有變更的鍵', async () => {
    const form = await loaded()
    form.formValues.value.password_min_length = 14

    await form.save()

    expect(updateSecurityPolicies).toHaveBeenCalledWith({ password_min_length: '14' })
  })

  it('套用過預覽時，送出前以同一個請求重打一次預覽', async () => {
    const changes = [
      { key: 'password_min_length', current: '8', proposed: '14', source_group: 'pci_dss_4_0_1' },
    ]
    previewApplyPolicies.mockResolvedValue({
      data: { mode: 'strictest', changes, conflicts: [], unchanged_count: 1, unmapped_count: 0 },
    })
    const form = await loaded()

    await form.previewApply('strictest')
    form.acceptPreview(changes)
    await form.save()

    // 一次預覽、一次送出前重算
    expect(previewApplyPolicies).toHaveBeenCalledTimes(2)
    expect(previewApplyPolicies.mock.calls[1][0]).toEqual(previewApplyPolicies.mock.calls[0][0])
    expect(updateSecurityPolicies).toHaveBeenCalledWith({ password_min_length: '14' })
  })

  it('重打的預覽與畫面不同時不儲存，重開預覽並提示重看', async () => {
    const changes = [
      { key: 'password_min_length', current: '8', proposed: '14', source_group: 'pci_dss_4_0_1' },
    ]
    previewApplyPolicies.mockResolvedValueOnce({
      data: { mode: 'strictest', changes, conflicts: [], unchanged_count: 1, unmapped_count: 0 },
    })
    const form = await loaded()

    await form.previewApply('strictest')
    form.acceptPreview(changes)
    form.previewVisible.value = false

    // 期間別人把要求改嚴了：同一個請求算出來的建議值不一樣
    previewApplyPolicies.mockResolvedValueOnce({
      data: {
        mode: 'strictest',
        changes: [{ ...changes[0], proposed: '16' }],
        conflicts: [],
        unchanged_count: 1,
        unmapped_count: 0,
      },
    })
    await form.save()

    expect(updateSecurityPolicies).not.toHaveBeenCalled()
    expect(form.previewVisible.value).toBe(true)
    expect(form.previewData.value.changes[0].proposed).toBe('16')
    expect(messages.warning).toHaveBeenCalled()
  })

  // 審查反例（儲存前重打預覽的比對）：目前值從 8 變成 9、建議值仍是 14 時，「從什麼改成什麼」已經不同了，
  // 只比 key 與 proposed 看不出來
  it('目前值變了但建議值不變時，仍算過期而不儲存', async () => {
    const changes = [
      { key: 'password_min_length', current: '8', proposed: '14', source_group: 'pci_dss_4_0_1' },
    ]
    previewApplyPolicies.mockResolvedValueOnce({
      data: { mode: 'strictest', changes, conflicts: [], unchanged_count: 1, unmapped_count: 0 },
    })
    const form = await loaded()

    await form.previewApply('strictest')
    form.acceptPreview(changes)
    form.previewVisible.value = false

    previewApplyPolicies.mockResolvedValueOnce({
      data: {
        mode: 'strictest',
        changes: [{ ...changes[0], current: '9' }],
        conflicts: [],
        unchanged_count: 1,
        unmapped_count: 0,
      },
    })
    await form.save()

    expect(updateSecurityPolicies).not.toHaveBeenCalled()
    expect(form.previewVisible.value).toBe(true)
  })

  it('依據換了一組時也算過期', async () => {
    const changes = [
      { key: 'password_min_length', current: '8', proposed: '14', source_group: 'pci_dss_4_0_1' },
    ]
    previewApplyPolicies.mockResolvedValueOnce({
      data: { mode: 'strictest', changes, conflicts: [], unchanged_count: 1, unmapped_count: 0 },
    })
    const form = await loaded()

    await form.previewApply('strictest')
    form.acceptPreview(changes)

    previewApplyPolicies.mockResolvedValueOnce({
      data: {
        mode: 'strictest',
        changes: [{ ...changes[0], source_group: 'epayment_baseline' }],
        conflicts: [],
        unchanged_count: 1,
        unmapped_count: 0,
      },
    })
    await form.save()

    expect(updateSecurityPolicies).not.toHaveBeenCalled()
  })

  it('衝突集多出一項時也算過期', async () => {
    const changes = [
      { key: 'password_min_length', current: '8', proposed: '14', source_group: 'pci_dss_4_0_1' },
    ]
    previewApplyPolicies.mockResolvedValueOnce({
      data: { mode: 'strictest', changes, conflicts: [], unchanged_count: 1, unmapped_count: 0 },
    })
    const form = await loaded()

    await form.previewApply('strictest')
    form.acceptPreview(changes)

    previewApplyPolicies.mockResolvedValueOnce({
      data: {
        mode: 'strictest',
        changes,
        conflicts: [
          {
            key: 'lockout_max_attempts',
            reasons: [
              { group: 'pci_dss_4_0_1', comparator: 'max', expected: '5' },
              { group: 'epayment_baseline', comparator: 'max', expected: '0' },
            ],
          },
        ],
        unchanged_count: 1,
        unmapped_count: 0,
      },
    })
    await form.save()

    expect(updateSecurityPolicies).not.toHaveBeenCalled()
    expect(form.previewData.value.conflicts).toHaveLength(1)
  })

  // 重打失敗不是「一致」：那是沒有完成已裁決的差異檢查
  it('儲存前重打預覽失敗時不儲存，提示可重試', async () => {
    const changes = [
      { key: 'password_min_length', current: '8', proposed: '14', source_group: 'pci_dss_4_0_1' },
    ]
    previewApplyPolicies.mockResolvedValueOnce({
      data: { mode: 'strictest', changes, conflicts: [], unchanged_count: 1, unmapped_count: 0 },
    })
    const form = await loaded()

    await form.previewApply('strictest')
    form.acceptPreview(changes)

    previewApplyPolicies.mockRejectedValueOnce(new Error('boom'))
    await form.save()

    expect(updateSecurityPolicies).not.toHaveBeenCalled()
    expect(messages.warning).toHaveBeenCalledWith('applyPreview.recheckFailed')
    // 填好的值仍留在表單裡，可以再按一次儲存
    expect(form.formValues.value.password_min_length).toBe(14)
  })

  it('還原清掉未儲存的編輯與已套用的預覽', async () => {
    const changes = [
      { key: 'password_min_length', current: '8', proposed: '14', source_group: 'pci_dss_4_0_1' },
    ]
    const form = await loaded()
    form.acceptPreview(changes)

    form.resetForm()
    await form.save()

    expect(form.formValues.value.password_min_length).toBe(8)
    // 沒有套用過預覽就不必重打
    expect(previewApplyPolicies).not.toHaveBeenCalled()
  })
})
