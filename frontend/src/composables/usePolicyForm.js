import { computed, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  getSecurityPolicies,
  previewApplyPolicies,
  previewCompliance,
  updateSecurityPolicies,
} from '@/api/securityPolicies'
import { policyLabel, toApiValue, toFormValue } from '@/utils/policyFormat'
import { currentLocale, t } from '@/i18n'

// 草稿判定的去抖：每敲一下數字就打一次後端是浪費，等使用者停手再問一次即可
const DRAFT_DEBOUNCE_MS = 300

// 政策表單邏輯：五個設定域頁共用。
// sections 決定本頁承載的鍵子集；includeRest=true（僅安全政策母頁）時，
// 未歸任何域的鍵落到「其他」區塊，避免後端新增鍵靜默消失。
// dirty/套用/儲存全部以本頁鍵子集為範圍（分域套用語義）。
//
// 符合性判定一律由後端供給：列表回應帶每鍵對各生效組的判定，未儲存的編輯改打
// 草稿判定端點。前端不自己算一份——兩套邏輯會漂移，而分歧不會有任何一處報錯。
export function usePolicyForm(sections, { includeRest = false } = {}) {
  const loading = ref(false)
  const saving = ref(false)
  const policies = ref([])
  // 生效政策組（頁首列與套用選單用）
  const groups = ref([])
  // 鍵→判定：savedVerdicts 是已儲存值的判定，draftVerdicts 是草稿值的判定
  //（null＝目前沒有草稿，兩者不合併，畫面要分得出哪一個在說話）
  const savedVerdicts = ref({})
  const draftVerdicts = ref(null)
  // 草稿判定的取得狀態：''（沒有草稿）、'pending'、'ready'、'failed'
  const draftStatus = ref('')
  // formValues 為編輯中的值（int→number、bool→boolean、enum→string）
  const formValues = ref({})
  const savedValues = ref({})

  // 草稿判定的版本號。300 毫秒去抖擋得住「每敲一下打一次」，擋不住已送出的兩個
  // 請求倒序回來：先送 12 再送 14，12 的回應晚到就會把 14 的結果蓋掉。每次送出
  // 遞增版本，只有最後一次送出的回應能寫進畫面；還原與儲存也遞增，使在途回應失效
  let draftVersion = 0

  const invalidateDraft = () => {
    draftVersion += 1
    draftVerdicts.value = null
    draftStatus.value = ''
  }

  const groupVerdicts = (verdicts) => {
    const map = {}
    verdicts.forEach((verdict) => {
      if (!map[verdict.key]) map[verdict.key] = []
      map[verdict.key].push(verdict)
    })
    return map
  }

  const applyResponse = (response) => {
    policies.value = response.data
    groups.value = response.groups || []
    const verdicts = {}
    const values = {}
    response.data.forEach((policy) => {
      verdicts[policy.key] = policy.verdicts || []
      values[policy.key] = toFormValue(policy)
    })
    savedVerdicts.value = verdicts
    invalidateDraft()
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
        result.push({
          id: 'rest',
          title: t('policyForm.restSection'),
          hint: '',
          policies: rest,
        })
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

  // 有草稿時畫面上的判定改用草稿那一份，並標示為草稿
  const verdictsByKey = computed(() => draftVerdicts.value || savedVerdicts.value)
  const isDraftVerdicts = computed(() => draftVerdicts.value !== null)

  const groupNames = computed(() =>
    Object.fromEntries(groups.value.map((g) => [g.code, g.name || g.code]))
  )

  // 草稿覆蓋：只送有變更的鍵，後端以它蓋過現值後重算
  const draftPayload = () => {
    const draft = {}
    Object.keys(formValues.value).forEach((key) => {
      if (formValues.value[key] === savedValues.value[key]) return
      const policy = byKey.value[key]
      if (!policy) return
      draft[key] = toApiValue(policy, formValues.value[key])
    })
    return draft
  }

  let draftTimer = null

  const runDraftPreview = async () => {
    const draft = draftPayload()
    if (Object.keys(draft).length === 0) {
      invalidateDraft()
      return
    }
    draftVersion += 1
    const version = draftVersion
    draftStatus.value = 'pending'
    try {
      const response = await previewCompliance(draft)
      if (version !== draftVersion) return // 過期回應：期間又送了一次，或已還原／儲存
      draftVerdicts.value = groupVerdicts(response.data?.verdicts || [])
      draftStatus.value = 'ready'
    } catch (error) {
      if (version !== draftVersion) return
      // 拿不到就說拿不到。沿用上一份結果會讓畫面上的判定配著另一組輸入值，
      // 而那個組合從來沒有被任何一方算過
      draftVerdicts.value = null
      draftStatus.value = 'failed'
      console.error('草稿判定失敗:', error)
    }
  }

  watch(
    formValues,
    () => {
      if (draftTimer) clearTimeout(draftTimer)
      draftTimer = setTimeout(runDraftPreview, DRAFT_DEBOUNCE_MS)
    },
    { deep: true }
  )

  // 套用預覽：只算不寫。scope 限本頁鍵——一個按鈕改掉四個頁面的設定，
  // 管理者按下去之前看不出影響範圍
  const previewVisible = ref(false)
  const previewData = ref(null)
  const previewLoading = ref(false)
  // 最近一次預覽的請求（送出儲存前逐字重送，比對結果有沒有變）
  const previewRequest = ref(null)
  // 已填進表單的那一次預覽
  const appliedPreview = ref(null)

  const previewApply = async (mode, groupCode = '') => {
    const request = {
      scope: [...pageKeys.value],
      mode,
      group_code: groupCode || '',
      draft: draftPayload(),
    }
    previewLoading.value = true
    try {
      const response = await previewApplyPolicies(request)
      previewData.value = response.data
      previewRequest.value = request
      previewVisible.value = true
    } catch (error) {
      console.error('套用預覽失敗:', error)
    } finally {
      previewLoading.value = false
    }
  }

  // 確認套用只把 changes 填進表單，儲存仍走既有的批次流程與審計
  const acceptPreview = (changes) => {
    (changes || []).forEach((change) => {
      const policy = byKey.value[change.key]
      if (!policy) return
      formValues.value[change.key] = toFormValue({ ...policy, value: change.proposed })
    })
    appliedPreview.value = {
      request: previewRequest.value,
      changes: changes || [],
      conflicts: previewData.value?.conflicts || [],
    }
    ElMessage.info(t('applyPreview.filled'))
  }

  // 比對用的正規化：管理者看到的是「哪個設定、從什麼改成什麼、依據哪一組」，
  // 四欄任一變了畫面上那句話就不同了。只比 key 與 proposed 會漏掉「目前值從 12
  // 變成 13、建議值仍是 14」與「依據換了一組」這兩種變化
  const normalizeChanges = (changes) =>
    (changes || [])
      .map((change) => ({
        key: change.key || '',
        current: change.current ?? '',
        proposed: change.proposed ?? '',
        source_group: change.source_group || '',
      }))
      .sort((a, b) => a.key.localeCompare(b.key))

  // 衝突集也一起比：衝突鍵不在 changes 內，但它是「這幾項要自己決定」的那份清單，
  // 期間多出或少掉一項，管理者按儲存前看到的說明就不成立了
  const normalizeConflicts = (conflicts) =>
    (conflicts || [])
      .map((conflict) => ({
        key: conflict.key || '',
        reasons: (conflict.reasons || [])
          .map((r) => `${r.group || ''}|${r.comparator || ''}|${r.expected ?? ''}`)
          .sort(),
      }))
      .sort((a, b) => a.key.localeCompare(b.key))

  const samePreview = (fresh, applied) =>
    JSON.stringify(normalizeChanges(fresh.changes)) ===
      JSON.stringify(normalizeChanges(applied.changes)) &&
    JSON.stringify(normalizeConflicts(fresh.conflicts)) ===
      JSON.stringify(normalizeConflicts(applied.conflicts))

  // 儲存前重算一次預覽：預覽到按下儲存之間若有人改了設定，畫面上那份建議就過期了。
  // 重算失敗不能當成一致——那等於在沒有完成檢查的情況下宣稱檢查通過。停在原地
  // 並說明可以再按一次，使用者填好的值仍留在表單裡
  const applyPreviewStillMatches = async () => {
    const applied = appliedPreview.value
    let fresh
    try {
      fresh = (await previewApplyPolicies(applied.request)).data
    } catch (error) {
      console.error('儲存前重算套用預覽失敗:', error)
      ElMessage.warning(t('applyPreview.recheckFailed'))
      return false
    }
    if (samePreview(fresh, applied)) return true
    previewData.value = fresh
    previewVisible.value = true
    ElMessage.warning(t('applyPreview.staleMessage'))
    return false
  }

  const resetForm = () => {
    formValues.value = { ...savedValues.value }
    appliedPreview.value = null
    invalidateDraft()
  }

  const save = async () => {
    const changed = {}
    dirtyKeys.value.forEach((key) => {
      changed[key] = toApiValue(byKey.value[key], formValues.value[key])
    })

    if (appliedPreview.value && !(await applyPreviewStillMatches())) return

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
      appliedPreview.value = null
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
    pagePolicies,
    groups,
    groupNames,
    formValues,
    savedValues,
    verdictsByKey,
    isDraftVerdicts,
    draftStatus,
    visibleSections,
    pageKeys,
    dirtyKeys,
    isDirty,
    previewVisible,
    previewData,
    previewLoading,
    loadPolicies,
    previewApply,
    acceptPreview,
    resetForm,
    save,
    setRestExclude,
  }
}
