import { computed, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  getSecurityPolicies,
  updateSecurityPolicies,
} from '@/api/securityPolicies'
import {
  isNonCompliantEPayment,
  isNonCompliantValue,
  policyLabel,
  toApiValue,
  toFormValue,
} from '@/utils/policyFormat'
import { currentLocale, t } from '@/i18n'

// 政策表單邏輯：四個設定域頁共用。
// sections 決定本頁承載的鍵子集；includeRest=true（僅安全政策母頁）時，
// 未歸任何域的鍵落到「其他」區塊，避免後端新增鍵靜默消失。
// dirty/套用/儲存全部以本頁鍵子集為範圍（分域套用語義）。
export function usePolicyForm(sections, { includeRest = false } = {}) {
  const loading = ref(false)
  const saving = ref(false)
  const policies = ref([])
  // 後端全鍵偏離總數（母頁總覽用；子頁請用 pageDeviationCount）
  const totalDeviationCount = ref(0)
  // formValues 為編輯中的值（int→number、bool→boolean、enum→string）
  const formValues = ref({})
  const savedValues = ref({})

  const applyResponse = (response) => {
    policies.value = response.data
    totalDeviationCount.value = response.deviation_count
    const values = {}
    response.data.forEach((policy) => {
      values[policy.key] = toFormValue(policy)
    })
    formValues.value = { ...values }
    savedValues.value = { ...values }
  }

  const loadPolicies = async () => {
    loading.value = true
    try {
      applyResponse(await getSecurityPolicies())
    } catch (error) {
      console.error('載入安全政策失敗:', error)
    } finally {
      loading.value = false
    }
  }

  const byKey = computed(() =>
    Object.fromEntries(policies.value.map((p) => [p.key, p]))
  )

  // 已歸其他域的鍵集（母頁「其他」區塊排除用），由頁面以 setRestExclude 提供
  const restExclude = ref(new Set())
  const setRestExclude = (keys) => {
    restExclude.value = new Set(keys)
  }

  const visibleSections = computed(() => {
    const grouped = new Set()
    const result = sections
      .map((section) => {
        const items = section.keys
          .filter((key) => byKey.value[key])
          .map((key) => byKey.value[key])
        items.forEach((p) => grouped.add(p.key))
        return { ...section, policies: items }
      })
      .filter((section) => section.policies.length > 0)

    if (includeRest) {
      // 「其他」僅排除本頁未列的鍵中「已歸其他域」者以外的全部——由呼叫端
      // 傳入 knownKeys 過濾；未傳時沿舊行為（母頁重構前的單頁時期）
      const rest = policies.value.filter(
        (p) => !grouped.has(p.key) && !restExclude.value.has(p.key)
      )
      if (rest.length > 0) {
        result.push({ title: t('policyForm.restSection'), hint: '', policies: rest })
      }
    }
    return result
  })

  // 本頁鍵集＝sections 鍵 ∪（includeRest 時的「其他」鍵）
  const pageKeys = computed(() => {
    const keys = new Set()
    visibleSections.value.forEach((s) => s.policies.forEach((p) => keys.add(p.key)))
    return keys
  })

  const pagePolicies = computed(() =>
    policies.value.filter((p) => pageKeys.value.has(p.key))
  )

  const dirtyKeys = computed(() =>
    pagePolicies.value
      .filter((p) => formValues.value[p.key] !== savedValues.value[p.key])
      .map((p) => p.key)
  )

  const isDirty = computed(() => dirtyKeys.value.length > 0)

  // 本頁鍵子集偏離數（即時反映未儲存編輯，與列內標籤同源）
  const pageDeviationCount = computed(
    () =>
      pagePolicies.value.filter((p) =>
        isNonCompliantValue(p, formValues.value[p.key], savedValues.value[p.key])
      ).length
  )

  // 本頁鍵子集的電支基準偏離數（與 PCI 各自獨立，不合計）
  const pageEPaymentDeviationCount = computed(
    () =>
      pagePolicies.value.filter((p) =>
        isNonCompliantEPayment(p, formValues.value[p.key], savedValues.value[p.key])
      ).length
  )

  // 分域套用：只填入本頁鍵的 PCI 建議值，待使用者按儲存生效（可還原）
  const applyPagePCI = () => {
    pagePolicies.value.forEach((policy) => {
      if (!policy.pci_value) return
      formValues.value[policy.key] = toFormValue({
        ...policy,
        value: policy.pci_value,
      })
    })
    if (isDirty.value) {
      ElMessage.info(t('policyForm.pciApplied'))
    } else {
      ElMessage.success(t('policyForm.pciAllCompliant'))
    }
  }

  // 套用電支基準：填入的是後端算好的
  // **兩基準取嚴值** `strictest_value`，不是 `epayment_value`。
  //
  // 兩基準在部分項目上方向相反（密碼最小長度 PCI 要求 >=12、電支只要求 >=6），
  // 無條件填入電支值會把已設 12 的系統改成 6——「套用合規基準」反而降低安全性。
  // 取嚴的計算在後端單點完成，前端不重算（重算＝兩份會漂移的邏輯）
  const applyPageEPayment = () => {
    pagePolicies.value.forEach((policy) => {
      if (!policy.strictest_value) return
      formValues.value[policy.key] = toFormValue({
        ...policy,
        value: policy.strictest_value,
      })
    })
    if (isDirty.value) {
      ElMessage.info(t('policyForm.epaymentApplied'))
    } else {
      ElMessage.success(t('policyForm.epaymentAllCompliant'))
    }
  }

  const resetForm = () => {
    formValues.value = { ...savedValues.value }
  }

  const save = async () => {
    const changed = {}
    dirtyKeys.value.forEach((key) => {
      changed[key] = toApiValue(byKey.value[key], formValues.value[key])
    })

    // 放寬到停用鎖定屬高影響變更，明確確認（僅承載該鍵的頁會觸發）
    if (changed.lockout_max_attempts === '0') {
      try {
        await ElMessageBox.confirm(
          t('policyForm.lockoutDisableConfirm'),
          t('policyForm.lockoutDisableTitle'),
          {
            confirmButtonText: t('policyForm.disable'),
            cancelButtonText: t('policyForm.cancel'),
            type: 'warning',
          }
        )
      } catch {
        return
      }
    }

    // 保留天數收縮屬不可逆變更：從永久（0）
    // 或較大值改為較小的有限值，超出新窗的舊審計/錄影資料將於次日 02:00
    // 排程硬刪，且刪除不可還原。逐鍵比對舊值 → 收縮者明確確認
    const shrunk = Object.keys(changed)
      .filter((key) => key.startsWith('retention_'))
      .filter((key) => {
        const next = parseInt(changed[key], 10)
        const prev = parseInt(savedValues.value[key], 10)
        if (isNaN(next) || next <= 0) return false // 新值 0/非法＝永久或不縮
        return prev === 0 || prev > next // 舊為永久、或視窗變短
      })
      .map((key) => policyLabel(byKey.value[key]) || key)
    if (shrunk.length > 0) {
      try {
        // 列表連接隨語言（zh 頓號/en 逗號）；政策 label 為後端字串（change 3 收口）
        const keyList = new Intl.ListFormat(currentLocale(), {
          style: 'narrow',
          type: 'conjunction',
        }).format(shrunk)
        await ElMessageBox.confirm(
          t('policyForm.retentionShrinkConfirm', { keys: keyList }),
          t('policyForm.retentionShrinkTitle'),
          {
            confirmButtonText: t('policyForm.confirmApply'),
            cancelButtonText: t('policyForm.cancel'),
            type: 'warning',
          }
        )
      } catch {
        return
      }
    }

    saving.value = true
    try {
      applyResponse(await updateSecurityPolicies(changed))
      ElMessage.success(t('policyForm.saved'))
    } catch (error) {
      console.error('儲存安全政策失敗:', error)
    } finally {
      saving.value = false
    }
  }

  return {
    loading,
    saving,
    policies,
    formValues,
    savedValues,
    totalDeviationCount,
    visibleSections,
    pageKeys,
    dirtyKeys,
    isDirty,
    pageDeviationCount,
    pageEPaymentDeviationCount,
    loadPolicies,
    applyPagePCI,
    applyPageEPayment,
    resetForm,
    save,
    setRestExclude,
  }
}
