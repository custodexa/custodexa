import { computed, shallowRef } from 'vue'
import { getCapabilityGeneration } from '@/composables/useCapabilities'
import {
  previewOverlay,
  setPreviewOverlay,
  clearPreviewOverlay,
} from '@/utils/previewOverlay'

/**
 * 以此角色預覽：進入、作廢、離開與頁面狀態查詢。
 *
 * 覆蓋本身（權限集合）放在 `utils/previewOverlay.js`，由 `useCapabilities.can()` 讀取；
 * 本檔管理流程。預覽權限集合請求以「會話世代 + 預覽請求序號」作廢：登出、換帳號、
 * 離開預覽、離開發出請求的畫面、再次發出之後，先前請求的回應一律丟棄，
 * 不設覆蓋、不導航、不顯示任何說明。判斷集中在 `applyPreviewResponse`，呼叫端只看回傳值。
 */

let requestSeq = 0

/** 離開預覽後要在角色編輯頁顯示的提示：{ roleId, roleName } 或 null。 */
export const exitedNotice = shallowRef(null)

/** 發出預覽權限集合請求之前呼叫；回傳的 token 在回應抵達時交給 `applyPreviewResponse`。 */
export function beginPreviewRequest() {
  requestSeq += 1
  return { gen: getCapabilityGeneration(), seq: requestSeq }
}

/** 這個 token 對應的請求是否仍是有效的最後一次（失敗訊息只在仍有效時顯示）。 */
export function isPreviewRequestCurrent(token) {
  return !!token && token.gen === getCapabilityGeneration() && token.seq === requestSeq
}

/** 使在途的預覽請求作廢（元件卸載時呼叫）。 */
export function invalidatePreviewRequests() {
  requestSeq += 1
}

const isValidPreview = (r) =>
  r &&
  typeof r === 'object' &&
  r.role &&
  typeof r.role === 'object' &&
  r.role.id !== undefined &&
  r.role.id !== null &&
  typeof r.previewable === 'boolean' &&
  Array.isArray(r.permissions) &&
  r.permissions.every((p) => typeof p === 'string') &&
  (r.entry_states === undefined || Array.isArray(r.entry_states))

/**
 * 套用一份預覽權限集合回應。
 * - 回 `false`：回應已過期（世代或序號不符）或格式不合，什麼都沒做，呼叫端不得導航或提示。
 * - 回 `{ entered: false }`：伺服器回報不可預覽（超管），未設覆蓋。
 * - 回 `{ entered: true }`：已設覆蓋，呼叫端導到儀表板。
 */
export function applyPreviewResponse(token, response) {
  if (!isPreviewRequestCurrent(token)) return false
  if (!isValidPreview(response)) return false
  if (!response.previewable) return { entered: false }
  exitedNotice.value = null
  setPreviewOverlay({
    roleId: response.role.id,
    roleName: typeof response.role.name === 'string' ? response.role.name : '',
    permissions: new Set(response.permissions),
    entryStates: response.entry_states || [],
    range: null,
  })
  return { entered: true }
}

/**
 * 離開預覽：立即清覆蓋（回到本人能力，不發任何請求）並使在途請求作廢。
 * 回傳進入時的角色 `{ roleId, roleName }`（呼叫端據此導回編輯頁）；本來就不在預覽中回 null。
 */
export function exitPreview() {
  requestSeq += 1
  const overlay = previewOverlay.value
  if (!overlay) return null
  clearPreviewOverlay()
  const origin = { roleId: overlay.roleId, roleName: overlay.roleName }
  exitedNotice.value = origin
  return origin
}

/** 登出等會話結束流程：清覆蓋、作廢在途請求，不留離開提示。 */
export function cancelPreview() {
  requestSeq += 1
  clearPreviewOverlay()
  exitedNotice.value = null
}

/** 預覽範圍（資產節點 id；null 為不篩選）。只供前端篩選，不送給伺服器。 */
export function setPreviewRange(nodeId) {
  const overlay = previewOverlay.value
  if (!overlay) return
  setPreviewOverlay({ ...overlay, range: nodeId ?? null })
}

const stateOfPath = (entryStates, path) => {
  if (!Array.isArray(entryStates) || typeof path !== 'string') return null
  const clean = path.split(/[?#]/)[0]
  const exact = entryStates.find((e) => e.path === clean)
  if (exact) return exact.state
  // 詳情頁跟隨所屬入口：取最長的路徑前綴（/sessions/12 → /sessions）
  let best = null
  for (const e of entryStates) {
    if (clean.startsWith(`${e.path}/`) && (!best || e.path.length > best.path.length)) best = e
  }
  return best ? best.state : null
}

/** 目前頁（路徑）在預覽集合中的頁面狀態：'manage' | 'read' | 'available' | null。 */
export function previewPageState(path) {
  const overlay = previewOverlay.value
  return overlay ? stateOfPath(overlay.entryStates, path) : null
}

export function useRolePreview() {
  return {
    overlay: previewOverlay,
    active: computed(() => previewOverlay.value !== null),
    roleId: computed(() => previewOverlay.value?.roleId ?? null),
    roleName: computed(() => previewOverlay.value?.roleName ?? ''),
    range: computed(() => previewOverlay.value?.range ?? null),
    exitedNotice,
    begin: beginPreviewRequest,
    invalidate: invalidatePreviewRequests,
    apply: applyPreviewResponse,
    exit: exitPreview,
    setRange: setPreviewRange,
    pageState: previewPageState,
  }
}
