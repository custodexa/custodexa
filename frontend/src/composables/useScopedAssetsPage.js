import { ref, computed } from 'vue'
import {
  hasActions,
  actionAllowed,
  actionDenial,
  denialText,
  scopeState,
  buildNodeOptions,
  selectableIdSet,
  scopedUpdateNodeIds,
  scopedCreateNodeIds,
} from '@/utils/scopedAssets'

/**
 * 資產頁的範圍化呈現狀態。
 *
 * 全部依伺服器回應的欄位（management_scope、actions、selectable、selectable_all）運作，
 * 不走節點樹計算範圍；強制點在後端。非範圍化檢視者（列表沒有 management_scope、列沒有 actions）
 * 時本檔的狀態全為空值，資產頁行為與原本一致。
 *
 * @param {object} deps
 * @param {Function} deps.t               vue-i18n 的 t
 * @param {Function} deps.fetchNodes      (params) => Promise，即 getAssetGroups
 * @param {() => number} deps.total       列表 total
 * @param {() => boolean} deps.hasFilters 目前是否有篩選（空態只在無篩選時成立）
 */
export function useScopedAssetsPage({ t, fetchNodes, total, hasFilters }) {
  // 列表頂層 management_scope；null＝非範圍化檢視者
  const managementScope = ref(null)
  const scopedViewer = computed(() => managementScope.value !== null)
  const scopedEmpty = computed(
    () => scopeState(managementScope.value, total()) === 'empty' && !hasFilters()
  )

  function applyListResponse(resp) {
    const ms = resp?.management_scope
    managementScope.value = ms && typeof ms === 'object' ? ms : null
  }

  const rowCan = (row, key, globalAllowed) => actionAllowed(row, key, globalAllowed)
  const rowDenial = (row, key) => denialText(t, actionDenial(row, key))

  // 抽屜／新增對話框的範圍化表單狀態；null＝沿現行
  const scopedForm = ref(null)
  const purposeNodes = ref([])
  const selectableAll = ref(null)
  const purposeLoaded = ref(false)

  async function loadPurpose(purpose) {
    purposeLoaded.value = false
    selectableAll.value = null
    try {
      const res = await fetchNodes({ purpose })
      purposeNodes.value = res?.data || []
      selectableAll.value = typeof res?.selectable_all === 'boolean' ? res.selectable_all : null
      purposeLoaded.value = true
    } catch (err) {
      console.error('載入可選節點失敗:', err)
    }
  }

  /** 開新增對話框：範圍化檢視者才取用途清單。 */
  function beginCreate() {
    scopedForm.value = null
    purposeLoaded.value = false
    if (!scopedViewer.value) return
    scopedForm.value = { mode: 'create', original: [], outOfScope: 0, actions: null, extra: [] }
    void loadPurpose('asset_create')
  }

  /** 開編輯抽屜：列（或詳情）帶 actions 或頁面是範圍化檢視者時走伺服器遮蔽後的投影。 */
  function beginEdit(row) {
    scopedForm.value = null
    purposeLoaded.value = false
    if (!scopedViewer.value && !hasActions(row)) return
    const ids = [...(row.node_ids || [])]
    const paths = row.node_paths || []
    scopedForm.value = {
      mode: 'update',
      original: ids,
      outOfScope: Number(row.out_of_scope_node_count) || 0,
      actions: hasActions(row) ? row.actions : null,
      extra: ids.map((id, i) => ({ id, name: paths[i] || String(id) })),
    }
    void loadPurpose('asset_update')
  }

  function endScopedForm() {
    scopedForm.value = null
    purposeLoaded.value = false
  }

  // 用途清單到手後才切換到範圍化選項；之前沿用頁面既有的選項
  const scopedNodeOptions = computed(() =>
    scopedForm.value && purposeLoaded.value
      ? buildNodeOptions(purposeNodes.value, { extra: scopedForm.value.extra })
      : null
  )

  const nodeRequired = computed(() => !!scopedForm.value && selectableAll.value === false)

  /** 節點欄必填的判定：建立必須有節點；更新只在沒有範圍外歸屬可保留時才要求。 */
  function nodesMissing(selected) {
    if (!nodeRequired.value) return false
    if ((selected || []).length > 0) return false
    return scopedForm.value.mode === 'create' || scopedForm.value.outOfScope === 0
  }

  /**
   * 送出本文的 node_ids。回傳 { include, value }：
   * include=false 代表本文不帶此鍵（範圍化編輯沒動節點欄）。
   */
  function submitNodeIds(selected) {
    if (!scopedForm.value) return { include: true, value: selected }
    if (!purposeLoaded.value) {
      // 沒拿到可選清單就不送節點欄（更新）；建立沿選取值，由伺服器裁決
      return scopedForm.value.mode === 'update'
        ? { include: false }
        : { include: true, value: selected }
    }
    const sel = selectableIdSet(scopedNodeOptions.value)
    if (scopedForm.value.mode === 'create') {
      return { include: true, value: scopedCreateNodeIds(selected, sel) }
    }
    const v = scopedUpdateNodeIds(selected, scopedForm.value.original, sel)
    return v === undefined ? { include: false } : { include: true, value: v }
  }

  return {
    managementScope,
    scopedViewer,
    scopedEmpty,
    applyListResponse,
    rowCan,
    rowDenial,
    scopedForm,
    scopedNodeOptions,
    nodeRequired,
    nodesMissing,
    beginCreate,
    beginEdit,
    endScopedForm,
    submitNodeIds,
  }
}
