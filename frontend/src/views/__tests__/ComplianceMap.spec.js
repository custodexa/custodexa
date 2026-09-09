import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount, RouterLinkStub } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import i18n from '@/i18n'
import ComplianceMap from '../ComplianceMap.vue'

enableAutoUnmount(afterEach)

const getComplianceSnapshotMock = vi.fn()
const getSecurityPoliciesMock = vi.fn()

vi.mock('@/api/compliance', () => ({
  getComplianceSnapshot: (...a) => getComplianceSnapshotMock(...a),
}))

vi.mock('@/api/securityPolicies', () => ({
  getSecurityPolicies: (...a) => getSecurityPoliciesMock(...a),
  updateSecurityPolicies: vi.fn(),
}))

// 判定理由的譯文由設定頁抽屜那一側提供，本波可能晚於本頁落地：
// 測試自備最小 messages，證明「有譯文時顯示人話」；未知碼的退路另有一案
i18n.global.mergeLocaleMessage('zh-TW', {
  verdictReason: { below_minimum: '低於要求' },
})

const setUser = (roles) => {
  localStorage.setItem('user', JSON.stringify({ id: 1, username: 'tester', roles }))
}

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
    enabled: false,
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
        id: 1,
        group_code: 'pci_dss_4_0_1',
        clause_no: '8.3.6',
        policy_key: 'password_min_length',
        comparator: 'min',
        expected_value: '12',
        reference_only: false,
      },
    ],
  },
  {
    group_code: 'pci_dss_4_0_1',
    clause_no: '4.2.1',
    title: '傳輸使用足夠強度的加密',
    summary: '',
    kind: 'setting',
    removed_in_version: '',
    controls: [
      {
        id: 2,
        group_code: 'pci_dss_4_0_1',
        clause_no: '4.2.1',
        policy_key: 'transport_rdp_level',
        comparator: 'review',
        expected_value: '',
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
        id: 3,
        group_code: 'pci_dss_4_0_1',
        clause_no: '8.3.9',
        policy_key: 'password_max_age_days',
        comparator: 'max',
        expected_value: '90',
        reference_only: true,
      },
    ],
    annotation: {
      group_code: 'pci_dss_4_0_1',
      clause_no: '8.3.9',
      note: '本機構以年度風險分析決定週期',
      confirmed_by: 'admin',
      confirmed_at: '2026-09-01T02:00:00Z',
      confirmation_note: '已於年度風險分析中決定',
    },
  },
  {
    group_code: 'pci_dss_4_0_1',
    clause_no: '10.2.1',
    title: '稽核軌跡涵蓋所有存取',
    summary: '',
    kind: 'builtin_protection',
    removed_in_version: '',
    controls: [],
  },
  {
    group_code: 'pci_dss_4_0_1',
    clause_no: '12.8.1',
    title: '服務供應商清單由機構維護',
    summary: '',
    kind: 'self_attested',
    removed_in_version: '',
    controls: [],
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
]

const VERDICTS = [
  {
    key: 'password_min_length',
    group_code: 'pci_dss_4_0_1',
    clause_no: '8.3.6',
    result: 'deviating',
    reason: 'below_minimum',
    current: '10',
    expected: '12',
    comparator: 'min',
    updated_by: 'policy-admin',
    updated_at: '2026-09-08T01:02:03Z',
    // 判定回應帶顯示中繼資料：同一頁上混著天、秒、分鐘與字元，只印「10」讀不出來
    unit_key: 'chars',
  },
  {
    key: 'transport_rdp_level',
    group_code: 'pci_dss_4_0_1',
    clause_no: '4.2.1',
    result: 'review',
    reason: 'expectation_unspecified',
    current: 'warn',
    comparator: 'review',
  },
  {
    key: 'password_max_age_days',
    group_code: 'pci_dss_4_0_1',
    clause_no: '8.3.9',
    result: 'needs_review',
    reason: 'reference_value_confirmed',
    current: '365',
    expected: '90',
    comparator: 'max',
    confirmed_by: 'admin',
    confirmed_at: '2026-09-01T02:00:00Z',
    unit_key: 'days',
    zero_disables: true,
  },
]

const snapshotResponse = () => ({
  data: {
    built_at: '2026-09-09T11:15:03Z',
    draft: false,
    groups: [
      { code: 'pci_dss_4_0_1', version: '4.0.1', enabled: true },
      { code: 'house_rules', version: '', enabled: false },
    ],
    verdicts: VERDICTS,
    unmapped_keys: ['k8s_list_timeout_seconds', 'retention_alert_days'],
    key_count: 55,
    builtin_protection_clauses: { pci_dss_4_0_1: 1 },
  },
  groups: GROUPS,
  summaries: [
    {
      group_code: 'pci_dss_4_0_1',
      compliant: 9,
      deviating: 1,
      needs_review: 1,
      audit_review: 1,
      unmapped: 24,
      builtin_protection: 1,
    },
  ],
  clauses: CLAUSES,
})

const mountPage = () =>
  mount(ComplianceMap, {
    global: {
      plugins: [ElementPlus],
      stubs: { RouterLink: RouterLinkStub },
    },
  })

describe('ComplianceMap 合規對照頁（稽核視角、唯讀）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    getComplianceSnapshotMock.mockResolvedValue(snapshotResponse())
    getSecurityPoliciesMock.mockResolvedValue({
      data: [
        {
          key: 'password_min_length',
          label: '密碼最小長度',
          type: 'int',
          value: '10',
          updated_by: 'admin',
          updated_at: '2026-09-08T01:02:03Z',
        },
      ],
    })
  })

  it('auditor 渲染下除搜尋欄與按鈕以外沒有任何寫入控制', async () => {
    setUser(['auditor'])
    const wrapper = mountPage()
    await flushPromises()

    // 唯一的輸入欄是設定名稱搜尋（唯讀的定位工具，不寫任何東西）
    const inputs = wrapper.findAll('input')
    expect(inputs).toHaveLength(1)
    expect(wrapper.find('[data-test="setting-search"]').exists()).toBe(true)
    expect(wrapper.findAll('textarea')).toHaveLength(0)
    expect(wrapper.findAll('select')).toHaveLength(0)
    // 唯讀頁不得打管理端的政策列表（auditor 打了必 403）
    expect(getSecurityPoliciesMock).not.toHaveBeenCalled()
  })

  it('摘要六格與不在對照範圍的一行都在（分母不被當成符合）', async () => {
    setUser(['auditor'])
    const wrapper = mountPage()
    await flushPromises()

    const text = wrapper.text()
    for (const label of [
      '條文',
      '符合',
      '偏離',
      '待人工確認',
      '待稽核判讀',
      '系統內建保護',
    ]) {
      expect(text).toContain(label)
    }
    expect(wrapper.find('.unmapped-note').text()).toContain('24')
  })

  // 40 是條文數、3 是設定鍵數，混在一排時第一眼分不出來，稽核會把兩種單位相加
  it('摘要分成條文與設定兩組，每格帶單位', async () => {
    setUser(['auditor'])
    const wrapper = mountPage()
    await flushPromises()

    const titles = wrapper.findAll('.summary-group-title').map((n) => n.text())
    expect(titles).toEqual(['條文（單位：條）', '設定（單位：項）'])
    expect(wrapper.find('[data-test="summary-clauses"]').text()).toContain('條')
    expect(wrapper.find('[data-test="summary-builtinProtection"]').text()).toContain('條')
    expect(wrapper.find('[data-test="summary-compliant"]').text()).toContain('項')
    expect(wrapper.find('[data-test="summary-auditReview"]').text()).toContain('項')
  })

  // 摘要說 3 條、清單只列 2 條，差額是不逐條列出的內建保護。
  // 格內不寫這句，讀者得自己相減才知道兩處為何對不上
  it('本組條文格註明其中幾條是內建保護，不必自己相減', async () => {
    setUser(['auditor'])
    const wrapper = mountPage()
    await flushPromises()

    const cell = wrapper.find('[data-test="summary-clauses"]')
    expect(cell.find('.summary-note').text()).toContain('1')
    expect(cell.find('.summary-note').text()).toContain('內建保護')
  })

  it('點重新整理會重新載入判定快照', async () => {
    setUser(['auditor'])
    const wrapper = mountPage()
    await flushPromises()
    expect(getComplianceSnapshotMock).toHaveBeenCalledTimes(1)

    await wrapper.find('[data-test="compliance-refresh"]').trigger('click')
    await flushPromises()

    expect(getComplianceSnapshotMock).toHaveBeenCalledTimes(2)
  })

  it('建構時點與時區都呈現（時區在次要位置）', async () => {
    setUser(['auditor'])
    const wrapper = mountPage()
    await flushPromises()

    expect(wrapper.find('.built-at').text()).toContain('2026')
    expect(wrapper.find('.built-at-timezone').exists()).toBe(true)
  })

  it('記錄連結帶資源與鍵的篩選參數（三步追證的第三步）', async () => {
    setUser(['auditor'])
    const wrapper = mountPage()
    await flushPromises()

    const targets = wrapper.findAllComponents(RouterLinkStub).map((l) => l.props('to'))
    expect(
      targets.some(
        (to) =>
          String(to).includes('/audit-logs') &&
          String(to).includes('resource=security_policy') &&
          String(to).includes('key=password_min_length')
      )
    ).toBe(true)
  })

  it('只看偏離只留下偏離的條文', async () => {
    setUser(['auditor'])
    const wrapper = mountPage()
    await flushPromises()

    expect(wrapper.text()).toContain('傳輸加密強制等級')

    await wrapper.find('.only-deviating button').trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('密碼複雜度')
    expect(wrapper.text()).not.toContain('傳輸加密強制等級')
  })

  it('條文層：標題先行、條號退為小字、對照鍵數可見', async () => {
    setUser(['auditor'])
    const wrapper = mountPage()
    await flushPromises()

    const titles = wrapper.findAll('.clause-title').map((n) => n.text())
    expect(titles[0]).toContain('密碼複雜度')
    expect(titles[0]).not.toContain('8.3.6')
    expect(wrapper.findAll('.clause-no').map((n) => n.text()).join(' ')).toContain('8.3.6')
  })

  // 內建組條文的文字有三語譯文，資料庫存的中文正本只是查無譯文時的備援。
  // 後端回什麼就顯示什麼的話，英日語使用者在這一頁只會看到中文。
  it('內建組條文以譯文顯示，不用後端回的中文正本', async () => {
    setUser(['auditor'])
    const wrapper = mountPage()
    await flushPromises()

    expect(wrapper.text()).not.toContain('密碼長度足夠')
  })

  it('譯文查無的條文回落後端文字（已自規範移除者仍讀得到）', async () => {
    setUser(['auditor'])
    const wrapper = mountPage()
    await flushPromises()

    expect(wrapper.text()).toContain('服務供應商清單由機構維護')
  })

  it('未定值的要求顯示為待稽核判讀，並列出目前值', async () => {
    setUser(['auditor'])
    const wrapper = mountPage()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('有要求但不定值，由稽核判讀')
    expect(text).toContain('待稽核判讀')
  })

  it('偏離的理由以人話呈現（查無譯文時退回原碼）', async () => {
    setUser(['auditor'])
    const wrapper = mountPage()
    await flushPromises()
    expect(wrapper.text()).toContain('低於要求')

    getComplianceSnapshotMock.mockResolvedValue({
      ...snapshotResponse(),
      data: {
        ...snapshotResponse().data,
        verdicts: [{ ...VERDICTS[0], reason: 'never_seen_before_code' }],
      },
    })
    const second = mountPage()
    await flushPromises()
    expect(second.text()).toContain('never_seen_before_code')
  })

  it('機構備註與確認資訊隨條文呈現', async () => {
    setUser(['auditor'])
    const wrapper = mountPage()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('本機構以年度風險分析決定週期')
    expect(text).toContain('已確認')
    expect(text).toContain('admin')
  })

  it('系統內建保護型條文只進摘要、不進條文清單；已移除條文不列', async () => {
    setUser(['auditor'])
    const wrapper = mountPage()
    await flushPromises()

    const text = wrapper.text()
    expect(text).not.toContain('稽核軌跡涵蓋所有存取')
    expect(text).not.toContain('已自規範移除的舊條文')
    expect(text).toContain('服務供應商清單由機構維護')
  })

  it('未生效的政策組以停用態出現在切換列', async () => {
    setUser(['auditor'])
    const wrapper = mountPage()
    await flushPromises()

    const chips = wrapper.findAll('.group-chip button')
    expect(chips.length).toBe(2)
    const disabled = chips.filter((c) => c.attributes('disabled') !== undefined)
    expect(disabled).toHaveLength(1)
    expect(wrapper.text()).toContain('未生效')
  })

  it('產出報告入口為停用態並說明尚未開放', async () => {
    setUser(['admin'])
    const wrapper = mountPage()
    await flushPromises()

    const slot = wrapper.find('.report-slot')
    expect(slot.attributes('title')).toContain('下一期')
    expect(slot.find('button').attributes('disabled')).toBeDefined()
  })

  // 三步追證的第二步：最後變更取自判定結果本身，兩種角色讀的是同一份結果。
  // 改自管理端的政策列表取（auditor 讀不到那一支）會讓稽核視角只看到「—」
  it('最後變更取自判定結果，auditor 與 admin 都看得到時間與操作者', async () => {
    for (const role of ['auditor', 'admin']) {
      localStorage.clear()
      setUser([role])
      const wrapper = mountPage()
      await flushPromises()

      const lastChange = wrapper.findAll('.last-change').map((n) => n.text())
      expect(lastChange.some((text) => text.includes('policy-admin'))).toBe(true)
      expect(lastChange.some((text) => text.includes('2026'))).toBe(true)
      // 判定結果已帶最後變更，不再另打管理端的政策列表
      expect(getSecurityPoliciesMock).not.toHaveBeenCalled()
      wrapper.unmount()
    }
  })

  // 三步追證的第一步：只知道設定叫什麼的稽核人員，不必猜它寫在哪一條
  it('搜尋設定名稱後展開所屬條文並標出該列', async () => {
    setUser(['auditor'])
    const wrapper = mountPage()
    await flushPromises()

    // 收合狀態下看不到設定名，也沒有任何列被標起來
    expect(wrapper.findAll('.key-row-hit')).toHaveLength(0)

    await wrapper.find('[data-test="setting-search"]').setValue('密碼最小長度')
    await wrapper.find('[data-test="setting-search-submit"]').trigger('click')
    await flushPromises()

    expect(wrapper.find('[data-test="setting-search-note"]').text()).toContain('1')
    const hit = wrapper.find('[data-test="key-row-password_min_length"]')
    expect(hit.exists()).toBe(true)
    expect(hit.classes()).toContain('key-row-hit')
    // 其他鍵在同一份清單裡但沒有被標
    expect(
      wrapper.find('[data-test="key-row-transport_rdp_level"]').classes()
    ).not.toContain('key-row-hit')
  })

  it('以英文鍵名也搜得到；重設後標示與展開一併清掉', async () => {
    setUser(['auditor'])
    const wrapper = mountPage()
    await flushPromises()

    await wrapper.find('[data-test="setting-search"]').setValue('transport_rdp')
    await wrapper.find('[data-test="setting-search-submit"]').trigger('click')
    await flushPromises()
    expect(
      wrapper.find('[data-test="key-row-transport_rdp_level"]').classes()
    ).toContain('key-row-hit')

    await wrapper.find('[data-test="setting-search-reset"]').trigger('click')
    await flushPromises()
    expect(wrapper.findAll('.key-row-hit')).toHaveLength(0)
    expect(wrapper.find('[data-test="setting-search-note"]').exists()).toBe(false)
  })

  it('查無設定時說找不到，不靜默什麼都不做', async () => {
    setUser(['auditor'])
    const wrapper = mountPage()
    await flushPromises()

    await wrapper.find('[data-test="setting-search"]').setValue('沒有這個設定')
    await wrapper.find('[data-test="setting-search-submit"]').trigger('click')
    await flushPromises()

    expect(wrapper.find('[data-test="setting-search-note"]').text()).toBe('找不到符合的設定')
  })

  // 只看標籤的非專業讀者會以為「待稽核判讀」與「機構自述」都只是等著誰按確認
  it('待稽核判讀與機構自述展開後各有一句固定說明', async () => {
    setUser(['auditor'])
    const wrapper = mountPage()
    await flushPromises()

    expect(wrapper.find('[data-test="clause-review-note-4.2.1"]').text()).toBe(
      '有目前設定值，無固定要求，由稽核判讀'
    )
    expect(wrapper.find('[data-test="clause-kind-note-12.8.1"]').text()).toBe(
      '由機構說明，系統不判定'
    )
    // 有固定要求的條文不長出這一句
    expect(wrapper.find('[data-test="clause-review-note-8.3.6"]').exists()).toBe(false)
  })

  // 同一頁混用天、秒、分鐘與字元；只印「10」與「0」，非專業人士判讀不出來
  it('目前值與要求值帶單位，零值另說語義', async () => {
    setUser(['auditor'])
    const wrapper = mountPage()
    await flushPromises()

    const row = wrapper.find('[data-test="key-row-password_min_length"]')
    const cells = row.findAll('td').map((c) => c.text())
    expect(cells[1]).toBe('10 字元')
    expect(cells[2]).toContain('12 字元')

    getComplianceSnapshotMock.mockResolvedValue({
      ...snapshotResponse(),
      data: {
        ...snapshotResponse().data,
        verdicts: [{ ...VERDICTS[2], current: '0' }],
      },
    })
    const zero = mountPage()
    await flushPromises()
    expect(zero.find('[data-test="key-row-password_max_age_days"]').findAll('td')[1].text()).toBe(
      '0 天（不啟用這項限制）'
    )
    zero.unmount()
  })

  it('從未變更過的鍵不假造一筆變更', async () => {
    setUser(['auditor'])
    const wrapper = mountPage()
    await flushPromises()

    // transport_rdp_level 的判定沒帶 updated_at
    const lastChange = wrapper.findAll('.last-change').map((n) => n.text())
    expect(lastChange).toContain('—')
  })
})
