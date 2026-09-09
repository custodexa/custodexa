import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import ApplyPreviewDialog from '../ApplyPreviewDialog.vue'

// 逐測卸載：殘留元件會讓後續測試耗時隨序累積
enableAutoUnmount(afterEach)

// el-dialog teleport 到 body，happy-dom 下 wrapper 撈不到——就地渲染的替身保留
// 預設插槽與 footer，斷言仍看得到真實文案與真實按鈕
const dialogStub = {
  props: ['modelValue', 'title'],
  template:
    '<div v-if="modelValue" class="dialog-stub"><h3>{{ title }}</h3><slot /><slot name="footer" /></div>',
}

const POLICIES = [
  {
    key: 'password_min_length',
    type: 'int',
    label: '密碼最小長度',
    unit: '字元',
    unit_key: 'chars',
  },
  { key: 'mfa_required', type: 'enum', label: '多因子驗證強制範圍', enum_order: ['off', 'admin_only', 'all'] },
  { key: 'clipboard_send_enabled', type: 'bool', label: '剪貼簿貼入資產' },
]

const PREVIEW = {
  mode: 'strictest',
  changes: [
    {
      key: 'password_min_length',
      current: '8',
      proposed: '14',
      source_group: 'house_rules',
    },
  ],
  conflicts: [
    {
      key: 'clipboard_send_enabled',
      reasons: [
        { group: 'pci_dss_4_0_1', expected: 'true', comparator: 'equals' },
        { group: 'epayment_baseline', expected: 'false', comparator: 'equals' },
      ],
    },
  ],
  unchanged_count: 7,
  unmapped_count: 3,
}

// 三個鍵各一種結果：偏離（在變動清單裡）、待稽核判讀、符合。
// 後端的 unchanged_count 把後兩者混在一起算，畫面不能照抄
const VERDICTS_BY_KEY = {
  password_min_length: [
    { key: 'password_min_length', group_code: 'house_rules', result: 'deviating' },
  ],
  mfa_required: [{ key: 'mfa_required', group_code: 'pci_dss_4_0_1', result: 'review' }],
  clipboard_send_enabled: [
    { key: 'clipboard_send_enabled', group_code: 'pci_dss_4_0_1', result: 'compliant' },
  ],
}

const mountDialog = (props = {}) =>
  mount(ApplyPreviewDialog, {
    global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub } },
    props: {
      modelValue: true,
      preview: PREVIEW,
      policies: POLICIES,
      pageTitle: '安全政策',
      groupNames: {
        pci_dss_4_0_1: 'PCI DSS 4.0.1',
        epayment_baseline: '支付基準組',
        house_rules: '內規',
      },
      verdictsByKey: VERDICTS_BY_KEY,
      ...props,
    },
  })

describe('ApplyPreviewDialog — 變動清單', () => {
  it('標題明示本頁，並說明只動本頁的設定', () => {
    const wrapper = mountDialog()
    expect(wrapper.find('h3').text()).toContain('安全政策')
    expect(wrapper.text()).toContain('只會變更「安全政策」這一頁的設定')
  })

  it('只列會變動的鍵，每列有設定名、目前、改成、依據的政策組', () => {
    const wrapper = mountDialog()

    const rows = wrapper.findAll('[data-test^="preview-change-"]')
    expect(rows).toHaveLength(1)
    const cells = rows[0].findAll('td').map((c) => c.text())
    expect(cells[0]).toBe('密碼最小長度')
    expect(cells[1]).toBe('8 字元')
    expect(cells[2]).toBe('14 字元')
    expect(cells[3]).toBe('內規')
    // 衝突鍵不在變動清單內
    expect(wrapper.find('[data-test="preview-change-clipboard_send_enabled"]').exists()).toBe(
      false
    )
  })

  it('沒有要變動也沒有衝突時說明沒有需要變更，確認鈕停用', () => {
    const wrapper = mountDialog({
      preview: { ...PREVIEW, changes: [], conflicts: [] },
    })

    expect(wrapper.text()).toContain('沒有需要變更的設定')
    const confirm = wrapper.findAll('button').find((b) => b.text() === '填入表單')
    expect(confirm.attributes('disabled')).toBeDefined()
  })

  // 零變動加上衝突不是「這一頁沒事」：那幾條規則是牴觸到不能自動改，
  // 兩種情形寫成同一句話會讓管理者以為已經符合
  it('零變動但有衝突時不說已符合，改說沒有可自動變更的項目', () => {
    const wrapper = mountDialog({ preview: { ...PREVIEW, changes: [] } })

    const text = wrapper.text()
    expect(text).toContain('沒有可以自動變更的設定')
    expect(text).not.toContain('已經符合')
    // 衝突區仍在，管理者知道要自己決定哪一條
    expect(wrapper.find('[data-test="preview-conflict-clipboard_send_enabled"]').exists()).toBe(
      true
    )
  })
})

// 首用路徑實走發現：套用建議值把多因子放寬到所有人之後，尚未綁定的管理員
// 下次登入就進不來，而預覽上看不出這一項與其他幾項有什麼不同
describe('ApplyPreviewDialog — 會把人鎖在門外的變更', () => {
  const mfaChange = {
    key: 'mfa_required',
    current: 'admin_only',
    proposed: 'all',
    source_group: 'pci_dss_4_0_1',
  }

  it('多因子放寬到所有使用者時，該列就近顯示先確認管理員已綁定', () => {
    const wrapper = mountDialog({
      preview: { ...PREVIEW, changes: [...PREVIEW.changes, mfaChange] },
    })

    const warning = wrapper.find('[data-test="preview-warning-mfa_required"]')
    expect(warning.exists()).toBe(true)
    expect(warning.text()).toContain('管理員自己已完成綁定')
    // 警語在該列內，不是對話框底部的一段通則
    expect(
      wrapper.find('[data-test="preview-change-mfa_required"]').text()
    ).toContain('管理員')
  })

  it('其餘變更不長出警語（只針對會鎖住自己的那一項）', () => {
    const wrapper = mountDialog({
      preview: {
        ...PREVIEW,
        changes: [{ ...mfaChange, proposed: 'admin_only', current: 'off' }],
      },
    })

    expect(wrapper.find('[data-test="preview-warning-mfa_required"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="preview-warning-password_min_length"]').exists()).toBe(
      false
    )
  })
})

describe('ApplyPreviewDialog — 衝突', () => {
  it('以人話段落列出兩條規則的來源，並標示不自動改', () => {
    const wrapper = mountDialog()

    const conflict = wrapper.find('[data-test="preview-conflict-clipboard_send_enabled"]')
    expect(conflict.exists()).toBe(true)
    const text = conflict.text()
    expect(text).toContain('剪貼簿貼入資產')
    expect(text).toContain('PCI DSS 4.0.1')
    expect(text).toContain('支付基準組')
    // 兩邊各自要求什麼都要說出來（開關型以白話值呈現）
    expect(text).toContain('開啟')
    expect(text).toContain('關閉')
    expect(wrapper.text()).toContain('系統不會自動改')
  })

  it('沒有衝突時不長出衝突區', () => {
    const wrapper = mountDialog({ preview: { ...PREVIEW, conflicts: [] } })
    expect(wrapper.find('.preview-conflicts').exists()).toBe(false)
  })
})

describe('ApplyPreviewDialog — 底部與確認', () => {
  // 後端的 unchanged_count 是「不會被自動改動的鍵數」，裡面混著待稽核判讀與
  // 參考值——那兩種都還沒有人說符合。已符合的數字改由判定投影，兩者分開列
  it('已符合的數字取自判定，不用預覽的不變動數；待判讀另計', () => {
    const wrapper = mountDialog()

    // unchanged_count 是 7，但真正符合的只有 clipboard_send_enabled 一個鍵
    expect(wrapper.find('[data-test="preview-compliant"]').text()).toBe('1 項設定已符合')
    expect(wrapper.find('.preview-counts').text()).not.toContain('7')
    expect(wrapper.find('[data-test="preview-pending"]').text()).toContain(
      '1 項待判讀或待確認'
    )
    expect(wrapper.find('[data-test="preview-unmapped"]').text()).toContain(
      '另有 3 項不屬於任何政策組'
    )
  })

  it('沒有待判讀或待確認的鍵時不長出那一格', () => {
    const wrapper = mountDialog({
      verdictsByKey: {
        clipboard_send_enabled: [
          { key: 'clipboard_send_enabled', group_code: 'pci_dss_4_0_1', result: 'compliant' },
        ],
      },
    })

    expect(wrapper.find('[data-test="preview-pending"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="preview-compliant"]').text()).toContain('1 項設定已符合')
  })

  it('明說確認只會填進表單，還要按儲存', () => {
    expect(mountDialog().text()).toContain('確認後只會填進表單')
  })

  it('確認時把變動清單上拋，並關閉對話框', async () => {
    const wrapper = mountDialog()

    const confirm = wrapper.findAll('button').find((b) => b.text() === '填入表單')
    await confirm.trigger('click')

    expect(wrapper.emitted('confirm')).toHaveLength(1)
    expect(wrapper.emitted('confirm')[0][0]).toEqual(PREVIEW.changes)
    expect(wrapper.emitted('update:modelValue')).toContainEqual([false])
  })

  it('取消不上拋任何變動', async () => {
    const wrapper = mountDialog()

    const cancel = wrapper.findAll('button').find((b) => b.text() === '取消')
    await cancel.trigger('click')

    expect(wrapper.emitted('confirm')).toBeUndefined()
    expect(wrapper.emitted('update:modelValue')).toContainEqual([false])
  })
})
