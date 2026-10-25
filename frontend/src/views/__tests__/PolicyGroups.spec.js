import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessageBox } from 'element-plus'
import PolicyGroups from '../PolicyGroups.vue'
import { setCapabilitiesForTests } from '@/composables/useCapabilities'

// 政策組管理頁：政策組**所有寫入的唯一入口**。
//
// 必守的兩條線：內建組的條文不可經介面改（它隨產品版本維護，改了下次升級就沒了，
// 而機構會以為自己改過），刪除自建組走破壞性確認（連帶清掉條文、備註與確認記錄）。

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

const getComplianceSnapshotMock = vi.fn()
const getPolicyGroupsMock = vi.fn()
const getPolicyGroupMock = vi.fn()
const getSecurityPoliciesMock = vi.fn()
const setEnabledMock = vi.fn()
const createGroupMock = vi.fn()
const renameGroupMock = vi.fn()
const deleteGroupMock = vi.fn()
const deleteClauseMock = vi.fn()
const annotationMock = vi.fn()
const confirmClauseMock = vi.fn()

vi.mock('@/api/compliance', () => ({
  getComplianceSnapshot: (...a) => getComplianceSnapshotMock(...a),
}))

vi.mock('@/api/securityPolicies', () => ({
  getSecurityPolicies: (...a) => getSecurityPoliciesMock(...a),
  updateSecurityPolicies: vi.fn(),
}))

vi.mock('@/api/policyGroups', () => ({
  getPolicyGroups: (...a) => getPolicyGroupsMock(...a),
  getPolicyGroup: (...a) => getPolicyGroupMock(...a),
  setPolicyGroupEnabled: (...a) => setEnabledMock(...a),
  createPolicyGroup: (...a) => createGroupMock(...a),
  renamePolicyGroup: (...a) => renameGroupMock(...a),
  deletePolicyGroup: (...a) => deleteGroupMock(...a),
  deletePolicyClause: (...a) => deleteClauseMock(...a),
  upsertClauseAnnotation: (...a) => annotationMock(...a),
  confirmClause: (...a) => confirmClauseMock(...a),
  upsertPolicyClause: vi.fn(),
  getPolicyKeyDef: vi.fn().mockResolvedValue({ data: {} }),
}))

const GROUPS = [
  {
    code: 'pci_dss_4_0_1',
    name: 'PCI DSS 4.0.1',
    source: 'builtin',
    enabled: true,
    version: '4.0.1',
    locale: '',
  },
  {
    code: 'house_rules',
    name: '公司內規',
    source: 'custom',
    enabled: true,
    version: '',
    locale: 'zh-TW',
  },
]

const CLAUSES = [
  {
    group_code: 'pci_dss_4_0_1',
    clause_no: '8.3.6',
    title: '密碼長度足夠',
    summary: '',
    kind: 'setting',
    removed_in_version: '',
    controls: [
      {
        policy_key: 'password_min_length',
        comparator: 'min',
        expected_value: '12',
        reference_only: false,
      },
    ],
  },
  {
    group_code: 'pci_dss_4_0_1',
    clause_no: '8.3.9',
    title: '定期更換密碼',
    summary: '',
    kind: 'setting',
    removed_in_version: '',
    controls: [
      {
        policy_key: 'password_max_age_days',
        comparator: 'max',
        expected_value: '90',
        reference_only: true,
      },
    ],
  },
  {
    group_code: 'pci_dss_4_0_1',
    clause_no: '9.9.9',
    title: '已自規範移除的舊條文',
    summary: '',
    kind: 'setting',
    removed_in_version: '4.0.1',
    controls: [],
  },
  {
    group_code: 'house_rules',
    clause_no: '1',
    title: '密碼至少 14 字元',
    summary: '',
    kind: 'setting',
    removed_in_version: '',
    controls: [
      {
        policy_key: 'password_min_length',
        comparator: 'min',
        expected_value: '14',
        reference_only: false,
      },
    ],
    annotation: {
      group_code: 'house_rules',
      clause_no: '1',
      note: '年度稽核已說明',
      confirmed_by: '',
      confirmed_at: null,
      confirmation_note: '',
    },
  },
]

const MANAGER_CAPS = ['policygroup:view', 'policygroup:manage', 'securitypolicy:manage']

const mountPage = async () => {
  const wrapper = mount(PolicyGroups, {
    global: { plugins: [ElementPlus] },
  })
  await flushPromises()
  return wrapper
}

const selectGroup = async (wrapper, code) => {
  wrapper.vm.activeCode = code
  await flushPromises()
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.setItem('user', JSON.stringify({ id: 1, username: 'admin', roles: ['admin'] }))
  // 合規快照端點要合規檢視權限：本頁不得依賴它，一律模擬 403
  getComplianceSnapshotMock.mockRejectedValue(new Error('403'))
  getPolicyGroupsMock.mockResolvedValue({ data: GROUPS })
  getPolicyGroupMock.mockImplementation((code) =>
    Promise.resolve({
      data: { group: GROUPS.find((g) => g.code === code), clauses: CLAUSES.filter((c) => c.group_code === code) },
    })
  )
  setCapabilitiesForTests(MANAGER_CAPS)
  getSecurityPoliciesMock.mockResolvedValue({
    data: [{ key: 'password_min_length', label: '密碼最小長度', type: 'int' }],
  })
  setEnabledMock.mockResolvedValue({ data: {} })
  createGroupMock.mockResolvedValue({ data: {} })
  renameGroupMock.mockResolvedValue({ data: {} })
  deleteGroupMock.mockResolvedValue({ data: {} })
  deleteClauseMock.mockResolvedValue({ data: {} })
  annotationMock.mockResolvedValue({ data: {} })
  confirmClauseMock.mockResolvedValue({ data: {} })
})

describe('PolicyGroups 組卡', () => {
  it('內建與自建各顯示來源、版本或原文語言與條文數', async () => {
    const wrapper = await mountPage()
    const text = wrapper.text()

    expect(text).toContain('PCI DSS 4.0.1')
    expect(text).toContain('公司內規')
    expect(text).toContain('4.0.1')
    expect(text).toContain('產品內建')
    expect(text).toContain('機構自建')
    // 內建組三條（含一條已移除），自建組一條
    expect(wrapper.findAll('.group-card').length).toBe(2)
    expect(wrapper.findAll('.group-card')[0].text()).toContain('3')
  })

  it('切換生效開關即送出，內建組的開關同樣由機構決定', async () => {
    const wrapper = await mountPage()
    await wrapper.vm.toggleEnabled(GROUPS[0], false)
    await flushPromises()

    expect(setEnabledMock).toHaveBeenCalledWith('pci_dss_4_0_1', false)
  })

  it('刪除自建組走破壞性確認，且說明會一併移除的東西', async () => {
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const wrapper = await mountPage()

    await wrapper.vm.removeGroup(GROUPS[1])
    await flushPromises()

    expect(confirmSpy).toHaveBeenCalled()
    const [message, , options] = confirmSpy.mock.calls[0]
    expect(message).toContain('公司內規')
    expect(message).toContain('備註')
    expect(options.confirmButtonClass).toBe('el-button--danger')
    expect(deleteGroupMock).toHaveBeenCalledWith('house_rules')
    confirmSpy.mockRestore()
  })

  it('新增政策組送出代號、名稱與原文語言', async () => {
    const wrapper = await mountPage()
    wrapper.vm.openCreate()
    wrapper.vm.createForm.code = 'house_rules_2'
    wrapper.vm.createForm.name = '公司內規（二）'
    wrapper.vm.createForm.locale = 'zh-TW'
    await wrapper.vm.saveCreate()
    await flushPromises()

    expect(createGroupMock).toHaveBeenCalledWith(
      { code: 'house_rules_2', name: '公司內規（二）', locale: 'zh-TW' },
      { skipErrorToast: true }
    )
  })

  it('點重新整理會重新載入政策組與條文', async () => {
    const wrapper = await mountPage()
    expect(getPolicyGroupsMock).toHaveBeenCalledTimes(1)

    await wrapper.find('[data-test="policy-groups-refresh"]').trigger('click')
    await flushPromises()

    expect(getPolicyGroupsMock).toHaveBeenCalledTimes(2)
  })
})

describe('PolicyGroups 條文表', () => {
  it('內建組的條文沒有編輯與刪除鈕，只留備註', async () => {
    const wrapper = await mountPage()
    await selectGroup(wrapper, 'pci_dss_4_0_1')

    expect(wrapper.findAll('.clause-edit')).toHaveLength(0)
    expect(wrapper.findAll('.clause-delete')).toHaveLength(0)
    expect(wrapper.findAll('.clause-note').length).toBeGreaterThan(0)
    expect(wrapper.findAll('.add-clause')).toHaveLength(0)
  })

  it('自建組的條文可編輯、可刪除，也能新增', async () => {
    const wrapper = await mountPage()
    await selectGroup(wrapper, 'house_rules')

    expect(wrapper.findAll('.clause-edit').length).toBeGreaterThan(0)
    expect(wrapper.findAll('.clause-delete').length).toBeGreaterThan(0)
    expect(wrapper.findAll('.add-clause').length).toBeGreaterThan(0)
  })

  it('條文列顯示型別、對應設定與人話要求', async () => {
    const wrapper = await mountPage()
    await selectGroup(wrapper, 'house_rules')

    const text = wrapper.text()
    expect(text).toContain('設定要求')
    expect(text).toContain('密碼最小長度')
    expect(text).toContain('至少 14')
    expect(text).toContain('年度稽核已說明')
  })

  // 內建組條文有三語譯文，自建組只有機構自己寫的一種語言：同一張表上兩種
  // 來源必須各走各的，否則不是英日語使用者看到中文，就是機構的原文被蓋掉。
  it('內建組條文顯示譯文、自建組顯示機構原文', async () => {
    const wrapper = await mountPage()

    await selectGroup(wrapper, 'pci_dss_4_0_1')
    expect(wrapper.text()).toContain('密碼複雜度')
    expect(wrapper.text()).not.toContain('密碼長度足夠')

    await selectGroup(wrapper, 'house_rules')
    expect(wrapper.text()).toContain('密碼至少 14 字元')
  })

  it('已自規範移除的條文仍在表上並標示已移除', async () => {
    const wrapper = await mountPage()
    await selectGroup(wrapper, 'pci_dss_4_0_1')

    const text = wrapper.text()
    expect(text).toContain('已自規範移除的舊條文')
    expect(text).toContain('已移除')
  })

  it('刪除條文走破壞性確認', async () => {
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const wrapper = await mountPage()
    await selectGroup(wrapper, 'house_rules')

    await wrapper.vm.removeClause(CLAUSES[3])
    await flushPromises()

    expect(deleteClauseMock).toHaveBeenCalledWith('house_rules', '1')
    confirmSpy.mockRestore()
  })
})

describe('PolicyGroups 備註與人工確認', () => {
  it('備註寫入獨立端點，並提醒備註不改判定', async () => {
    const wrapper = await mountPage()
    await selectGroup(wrapper, 'house_rules')

    wrapper.vm.openNote(CLAUSES[3])
    await flushPromises()
    expect(wrapper.vm.noteForm.note).toBe('年度稽核已說明')
    expect(wrapper.text()).toContain('備註不影響判定')

    wrapper.vm.noteForm.note = '改成這樣'
    await wrapper.vm.saveNote()
    await flushPromises()
    expect(annotationMock).toHaveBeenCalledWith('house_rules', '1', '改成這樣')
  })

  it('只有待人工確認的條文出現確認鈕', async () => {
    const wrapper = await mountPage()
    await selectGroup(wrapper, 'pci_dss_4_0_1')
    // 三條裡只有參考值那一條可確認
    expect(wrapper.findAll('.clause-confirm')).toHaveLength(1)

    await selectGroup(wrapper, 'house_rules')
    expect(wrapper.findAll('.clause-confirm')).toHaveLength(0)
  })

  it('確認要有一句說明，缺說明不送出', async () => {
    const wrapper = await mountPage()
    await selectGroup(wrapper, 'pci_dss_4_0_1')

    wrapper.vm.openConfirm(CLAUSES[1])
    await wrapper.vm.saveConfirm()
    await flushPromises()
    expect(confirmClauseMock).not.toHaveBeenCalled()

    wrapper.vm.confirmForm.note = '已於年度風險分析中決定'
    await wrapper.vm.saveConfirm()
    await flushPromises()
    expect(confirmClauseMock).toHaveBeenCalledWith(
      'pci_dss_4_0_1',
      '8.3.9',
      '已於年度風險分析中決定'
    )
  })
})

describe('PolicyGroups 資料來源與唯讀呈現', () => {
  const WRITE_SELECTORS = [
    '.create-group', '.group-rename', '.group-delete', '.add-clause',
    '.clause-note', '.clause-confirm', '.clause-edit', '.clause-delete',
  ]

  it('只持政策組檢視：只讀政策組端點，不碰合規快照與設定清單', async () => {
    setCapabilitiesForTests(['policygroup:view'])
    const wrapper = await mountPage()

    expect(getPolicyGroupsMock).toHaveBeenCalledTimes(1)
    expect(getPolicyGroupMock).toHaveBeenCalledTimes(GROUPS.length)
    expect(getComplianceSnapshotMock).not.toHaveBeenCalled()
    expect(getSecurityPoliciesMock).not.toHaveBeenCalled()
    expect(wrapper.findAll('.group-card').length).toBe(2)
    expect(wrapper.text()).toContain('密碼複雜度')
  })

  it('系統安全管理員組合（無合規檢視）讀得到組與條文，並讀設定清單', async () => {
    const wrapper = await mountPage()

    expect(getComplianceSnapshotMock).not.toHaveBeenCalled()
    expect(getSecurityPoliciesMock).toHaveBeenCalledTimes(1)
    expect(wrapper.findAll('.group-card').length).toBe(2)
    expect(wrapper.text()).toContain('密碼複雜度')
  })

  it('寫入成功後重讀仍走政策組端點', async () => {
    const wrapper = await mountPage()
    await wrapper.vm.toggleEnabled(GROUPS[0], false)
    await flushPromises()

    expect(getPolicyGroupsMock).toHaveBeenCalledTimes(2)
    expect(getComplianceSnapshotMock).not.toHaveBeenCalled()
  })

  it('只持檢視：寫入動作不在 DOM，顯示唯讀說明、唯讀版內建說明與狀態標籤', async () => {
    setCapabilitiesForTests(['policygroup:view'])
    const wrapper = await mountPage()
    await selectGroup(wrapper, 'pci_dss_4_0_1')

    for (const sel of WRITE_SELECTORS) expect(wrapper.find(sel).exists(), sel).toBe(false)
    expect(wrapper.find('.el-switch').exists()).toBe(false)
    expect(wrapper.find('[data-test="policy-groups-readonly-note"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('內容不能修改')
    expect(wrapper.text()).not.toContain('可以加備註或做人工確認')
    expect(wrapper.findAll('.group-status').length).toBe(2)
    expect(wrapper.text()).toContain('生效中')
  })

  it('持檢視與管理：按鈕與開關齊全，沒有唯讀說明與狀態標籤', async () => {
    const wrapper = await mountPage()
    await selectGroup(wrapper, 'pci_dss_4_0_1')

    expect(wrapper.find('.create-group').exists()).toBe(true)
    expect(wrapper.find('.el-switch').exists()).toBe(true)
    expect(wrapper.find('.clause-note').exists()).toBe(true)
    expect(wrapper.find('[data-test="policy-groups-readonly-note"]').exists()).toBe(false)
    expect(wrapper.findAll('.group-status').length).toBe(0)
    expect(wrapper.text()).toContain('可以加備註或做人工確認')
  })
})
