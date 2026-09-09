import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import ClauseDialog from '@/components/ClauseDialog.vue'

// 條文對話框：機構把內規寫成一條一條要求的地方。
//
// 三件事非測不可：
//  1.「有要求但不定值」送出的是 review 與空值——送了值會被端點擋下，
//    而送成別的比較方式等於替條文發明一個它沒說過的門檻；
//  2. 超出值域的要求值在送出前就擋住並就近說明，不是等端點回 400；
//  3.「儲存後結果」說的是現值與這條要求的關係，錯了會讓人以為已經合規。

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

const upsertMock = vi.fn()
const defMock = vi.fn()
vi.mock('@/api/policyGroups', () => ({
  upsertPolicyClause: (...a) => upsertMock(...a),
  getPolicyKeyDef: (...a) => defMock(...a),
}))

// 「儲存後結果」走草稿判定端點（後端以 temp_controls 覆蓋同組同鍵的控制後重算）
const previewComplianceMock = vi.fn()
vi.mock('@/api/securityPolicies', () => ({
  previewCompliance: (...a) => previewComplianceMock(...a),
}))

const dialogStub = {
  props: ['modelValue'],
  template: '<div v-if="modelValue" class="dialog-stub"><slot /><slot name="footer" /></div>',
}

const POLICIES = [
  { key: 'password_min_length', label: '密碼最小長度', type: 'int' },
  { key: 'clipboard_send_enabled', label: '剪貼簿貼入資產', type: 'bool' },
  { key: 'login_banner_title', label: '登入告示標題', type: 'text' },
]

const INT_DEF = {
  key: 'password_min_length',
  type: 'int',
  value: '12',
  comparators: ['min', 'max', 'review'],
  min: 0,
  max: 128,
  unit_key: 'chars',
}

const BOOL_DEF = {
  key: 'clipboard_send_enabled',
  type: 'bool',
  value: 'true',
  comparators: ['equals', 'review'],
}

async function mountDialog(props = {}) {
  const wrapper = mount(ClauseDialog, {
    global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub } },
    props: { modelValue: false, groupCode: 'house_rules', policies: POLICIES, ...props },
  })
  await wrapper.setProps({ modelValue: true })
  await flushPromises()
  return wrapper
}

const pickKey = async (wrapper, index, key) => {
  wrapper.vm.controls[index].policy_key = key
  await wrapper.vm.loadDef(wrapper.vm.controls[index])
  await flushPromises()
}

beforeEach(() => {
  vi.clearAllMocks()
  upsertMock.mockResolvedValue({ data: {} })
  defMock.mockImplementation((key) =>
    Promise.resolve({ data: key === 'clipboard_send_enabled' ? BOOL_DEF : INT_DEF })
  )
  previewComplianceMock.mockResolvedValue({ data: { draft: true, verdicts: [] } })
})

describe('ClauseDialog 設定要求型條文', () => {
  it('選鍵後帶回型別、比較方式候選與目前值，要求欄預設為不定值', async () => {
    const wrapper = await mountDialog()
    await pickKey(wrapper, 0, 'password_min_length')

    expect(defMock).toHaveBeenCalledWith('password_min_length')
    expect(wrapper.vm.controls[0].def.comparators).toEqual(['min', 'max', 'review'])
    expect(wrapper.vm.controls[0].comparator).toBe('review')
  })

  it('不定值送出 review 且值為空（不替條文發明門檻）', async () => {
    const wrapper = await mountDialog()
    wrapper.vm.form.clause_no = '3-2'
    wrapper.vm.form.title = '傳輸須使用足夠強度的加密'
    await pickKey(wrapper, 0, 'password_min_length')
    // 曾填過值再改回不定值：值不得殘留
    wrapper.vm.controls[0].comparator = 'min'
    wrapper.vm.controls[0].expected_value = 14
    wrapper.vm.controls[0].comparator = 'review'

    await wrapper.vm.submit()
    await flushPromises()

    expect(upsertMock).toHaveBeenCalledTimes(1)
    const [code, clauseNo, payload] = upsertMock.mock.calls[0]
    expect(code).toBe('house_rules')
    expect(clauseNo).toBe('3-2')
    expect(payload.controls).toEqual([
      {
        policy_key: 'password_min_length',
        comparator: 'review',
        expected_value: '',
        reference_only: false,
      },
    ])
  })

  it('要求值超出值域就近紅字，且擋在送出之前', async () => {
    const wrapper = await mountDialog()
    wrapper.vm.form.clause_no = '3-3'
    wrapper.vm.form.title = '密碼長度'
    await pickKey(wrapper, 0, 'password_min_length')
    wrapper.vm.controls[0].comparator = 'min'
    wrapper.vm.controls[0].expected_value = 9999
    await flushPromises()

    const error = wrapper.find('.control-error')
    expect(error.exists()).toBe(true)
    expect(error.text()).toContain('128')

    await wrapper.vm.submit()
    await flushPromises()
    expect(upsertMock).not.toHaveBeenCalled()
  })

  // 「儲存後結果」由後端草稿判定端點算：前端曾自己實作一套整數方向、零值與
  // 明確值的比較，兩套邏輯漂移不會有任何一處報錯
  it('儲存後結果打草稿判定端點並帶臨時控制，結果原樣採用', async () => {
    const wrapper = await mountDialog()
    wrapper.vm.form.clause_no = '3-2'
    await pickKey(wrapper, 0, 'password_min_length')
    wrapper.vm.controls[0].comparator = 'min'
    wrapper.vm.controls[0].expected_value = 14
    // 監看到改動後先轉「判定中」並排入去抖；立即取問取代那一次
    await flushPromises()
    expect(wrapper.find('.after-save').text()).toContain('判定中')

    previewComplianceMock.mockResolvedValueOnce({
      data: {
        draft: true,
        verdicts: [
          {
            key: 'password_min_length',
            group_code: 'house_rules',
            clause_no: '3-2',
            result: 'deviating',
            current: '12',
            unit_key: 'chars',
          },
        ],
      },
    })
    await wrapper.vm.fetchAfterSave(wrapper.vm.controls[0])
    await flushPromises()

    expect(previewComplianceMock).toHaveBeenCalledWith({}, [
      {
        group_code: 'house_rules',
        clause_no: '3-2',
        policy_key: 'password_min_length',
        comparator: 'min',
        expected_value: '14',
        reference_only: false,
      },
    ])
    const text = wrapper.find('.after-save').text()
    expect(text).toContain('偏離')
    // 目前值取自判定回應，並帶單位
    expect(text).toContain('12 字元')

    // 後端改口說符合，畫面就跟著改口——前端沒有自己的一份答案
    previewComplianceMock.mockResolvedValueOnce({
      data: {
        draft: true,
        verdicts: [
          {
            key: 'password_min_length',
            group_code: 'house_rules',
            result: 'compliant',
            current: '12',
            unit_key: 'chars',
          },
        ],
      },
    })
    await wrapper.vm.fetchAfterSave(wrapper.vm.controls[0])
    await flushPromises()
    expect(wrapper.find('.after-save').text()).toContain('符合')
  })

  // 審查反例（值域錯誤不得預告儲存後結果）：值域紅字說這個值存不進去，同一列卻預告「儲存後符合」
  it('要求值超出值域時不打端點，也不預告儲存後的結果', async () => {
    const wrapper = await mountDialog()
    await pickKey(wrapper, 0, 'password_min_length')
    // 先取得一份合法的判定
    previewComplianceMock.mockResolvedValueOnce({
      data: {
        verdicts: [
          {
            key: 'password_min_length',
            group_code: 'house_rules',
            result: 'compliant',
            current: '12',
          },
        ],
      },
    })
    wrapper.vm.controls[0].comparator = 'min'
    wrapper.vm.controls[0].expected_value = 10
    await flushPromises()
    await wrapper.vm.fetchAfterSave(wrapper.vm.controls[0])
    await flushPromises()
    expect(wrapper.find('.after-save').text()).toContain('符合')

    // 改成超出值域：紅字出現，儲存後結果不得再說符合
    wrapper.vm.controls[0].expected_value = 9999
    await flushPromises()
    previewComplianceMock.mockClear()
    await wrapper.vm.fetchAfterSave(wrapper.vm.controls[0])
    await flushPromises()

    expect(previewComplianceMock).not.toHaveBeenCalled()
    expect(wrapper.find('.control-error').exists()).toBe(true)
    const text = wrapper.find('.after-save').text()
    expect(text).not.toContain('符合')
    expect(text).toContain('先修正上面的值')
  })

  it('判定拿不到時說判定沒回來，不沿用上一次的結果', async () => {
    const wrapper = await mountDialog()
    await pickKey(wrapper, 0, 'password_min_length')
    previewComplianceMock.mockResolvedValueOnce({
      data: {
        verdicts: [
          {
            key: 'password_min_length',
            group_code: 'house_rules',
            result: 'compliant',
            current: '12',
          },
        ],
      },
    })
    wrapper.vm.controls[0].comparator = 'min'
    wrapper.vm.controls[0].expected_value = 10
    await flushPromises()
    await wrapper.vm.fetchAfterSave(wrapper.vm.controls[0])
    await flushPromises()
    expect(wrapper.find('.after-save').text()).toContain('符合')

    wrapper.vm.controls[0].expected_value = 20
    await flushPromises()
    previewComplianceMock.mockRejectedValueOnce(new Error('boom'))
    await wrapper.vm.fetchAfterSave(wrapper.vm.controls[0])
    await flushPromises()

    const text = wrapper.find('.after-save').text()
    expect(text).toContain('判定沒有回來')
    expect(text).not.toContain('符合')
  })

  it('開關型只給明確值，沒有相對的強弱選項', async () => {
    const wrapper = await mountDialog()
    await pickKey(wrapper, 0, 'clipboard_send_enabled')

    expect(wrapper.vm.controls[0].def.comparators).toEqual(['equals', 'review'])
    expect(wrapper.vm.comparatorOptions(wrapper.vm.controls[0]).map((o) => o.value)).toEqual([
      'review',
      'equals',
    ])
  })

  it('自由文字型的鍵不出現在可選清單（沒有可比較的要求值）', async () => {
    const wrapper = await mountDialog()
    expect(wrapper.vm.selectableKeys.map((p) => p.key)).not.toContain('login_banner_title')
    expect(wrapper.vm.selectableKeys.map((p) => p.key)).toContain('password_min_length')
  })

  it('缺條號或標題一律擋在送出之前', async () => {
    const wrapper = await mountDialog()
    await pickKey(wrapper, 0, 'password_min_length')

    await wrapper.vm.submit()
    await flushPromises()
    expect(upsertMock).not.toHaveBeenCalled()

    wrapper.vm.form.clause_no = '3-4'
    await wrapper.vm.submit()
    await flushPromises()
    expect(upsertMock).not.toHaveBeenCalled()
  })
})

describe('ClauseDialog 由機構自行確認型條文', () => {
  it('不送任何要求（端點對這一型帶要求會拒收）', async () => {
    const wrapper = await mountDialog()
    wrapper.vm.form.clause_no = '4-1'
    wrapper.vm.form.title = '服務供應商清單由機構維護'
    wrapper.vm.form.kind = 'self_attested'
    await pickKey(wrapper, 0, 'password_min_length')

    await wrapper.vm.submit()
    await flushPromises()

    expect(upsertMock).toHaveBeenCalledTimes(1)
    expect(upsertMock.mock.calls[0][2].kind).toBe('self_attested')
    expect(upsertMock.mock.calls[0][2].controls).toEqual([])
  })
})

describe('ClauseDialog 編輯既有條文', () => {
  it('條號不可改，要求逐列回填', async () => {
    const wrapper = await mountDialog({
      clause: {
        group_code: 'house_rules',
        clause_no: '3-2',
        title: '密碼長度',
        summary: '內規要求 14 字元',
        kind: 'setting',
        controls: [
          {
            policy_key: 'password_min_length',
            comparator: 'min',
            expected_value: '14',
            reference_only: false,
          },
        ],
      },
    })
    await flushPromises()

    expect(wrapper.vm.form.clause_no).toBe('3-2')
    expect(wrapper.vm.isEdit).toBe(true)
    // 整數欄的輸入元件會把回填的字串正規化成數字；送出時再轉回字串
    expect(String(wrapper.vm.controls[0].expected_value)).toBe('14')
    expect(defMock).toHaveBeenCalledWith('password_min_length')
  })
})
