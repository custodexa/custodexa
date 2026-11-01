import { computed, shallowRef } from 'vue'

/**
 * 以此角色預覽的覆蓋狀態（只活在該分頁記憶體）。
 *
 * 本檔不 import 任何 API 或能力模組：`request.js` 與 `useCapabilities.js` 都要讀它，
 * 獨立成檔才不會形成模組環。覆蓋的進入、作廢與離開流程在 `useRolePreview.js`。
 *
 * 形狀：{ roleId, roleName, permissions: Set<string>, entryStates: Array, range: number|null }
 * 不寫入 localStorage／sessionStorage；重新整理、新分頁、登出都不帶預覽。
 */
export const previewOverlay = shallowRef(null)

/** 範本用的響應式旗標：預覽中為 true */
export const previewActive = computed(() => previewOverlay.value !== null)

export const getPreviewOverlay = () => previewOverlay.value

export const isPreviewActive = () => previewOverlay.value !== null

export function setPreviewOverlay(overlay) {
  previewOverlay.value = overlay
}

export function clearPreviewOverlay() {
  previewOverlay.value = null
}

/**
 * 預覽中仍照常送出的非 GET 讀取（經盤點列明、伺服器端不寫入任何資料）。
 * 簽發 token 或票證、對遠端主機執行動作的路由一律不得列入。
 * 每一條都是「方法 + 相對於 API 根的路徑」，完整比對、不做前綴比對。
 */
export const PREVIEW_ALLOWED_NON_GET = Object.freeze([
  Object.freeze({ method: 'POST', path: '/schedules/next-runs' }),
  Object.freeze({ method: 'POST', path: '/role-definitions/summary' }),
  Object.freeze({ method: 'POST', path: '/role-assignment-previews' }),
])

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

const pathOf = (url) => {
  const raw = typeof url === 'string' ? url : ''
  const cut = raw.search(/[?#]/)
  return cut === -1 ? raw : raw.slice(0, cut)
}

/** 預覽中這個請求是否應被攔下（不送出）。覆蓋不存在時恆為否。 */
export function shouldBlockInPreview(config) {
  if (!isPreviewActive()) return false
  const method = String(config?.method || 'get').toUpperCase()
  if (SAFE_METHODS.has(method)) return false
  const path = pathOf(config?.url)
  return !PREVIEW_ALLOWED_NON_GET.some((e) => e.method === method && e.path === path)
}
