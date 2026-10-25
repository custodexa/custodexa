import { computed, ref, shallowRef } from 'vue'
import { getCurrentUser } from '@/api/auth'
import { onSessionEnded } from '@/utils/session'

/**
 * 目前使用者能力的唯一狀態。
 *
 * 能力來自後端 GET／PATCH `/auth/me` 的 `permissions`（伺服器逐請求解析），前端只用 `can(perm)`
 * 做完整鍵的成員比對來決定「顯示什麼」；**強制點一律在後端**，改動或偽造這裡的集合不改變任何權限。
 *
 * - 不解析角色、不做前綴或萬用比對、不拿某個管理權當所有管理權。
 * - `ui:` 開頭的點是伺服器產生、不可指派的呈現點，不是角色能力。
 * - 載入前、載入失敗、欄位缺漏或型別錯誤時 `can()` 一律為否——**沒有角色回退**。
 * - 能力只活在記憶體；localStorage 的 user 快取可以留著顯示名稱，但不是能力的權威。
 * - GET／PATCH 成功整批替換，不與舊集合聯集；登出、續期終敗、切換帳號清空，
 *   並以「世代」丟棄前一個會話仍在途的回應。
 */

const permissionSet = shallowRef(null) // Set<string> | null（null＝尚未取得）
const scopeSummary = shallowRef([])
const status = ref('idle') // idle | loading | ready | error
const productVersion = ref('')
const loadedUserId = ref(null)

let generation = 0
let inflight = null

/** 目前使用者是否持有該權限點（完整鍵比對）。 */
export function can(perm) {
  return typeof perm === 'string' && perm !== '' && permissionSet.value instanceof Set && permissionSet.value.has(perm)
}

/** 全部都持有才為真；空清單視為無需求的呼叫錯誤，一律為否（fail-closed）。 */
export function canAll(perms) {
  return Array.isArray(perms) && perms.length > 0 && perms.every(can)
}

const isValidProjection = (info) =>
  info &&
  typeof info === 'object' &&
  Array.isArray(info.permissions) &&
  info.permissions.every((p) => typeof p === 'string') &&
  (info.scope_summary === undefined || Array.isArray(info.scope_summary))

// 與既有取用方式一致：攔截器回本文，個別測試與舊呼叫端可能包一層 data
const unwrap = (res) => (res?.data && typeof res.data === 'object' && !Array.isArray(res.data) ? res.data : res)

/**
 * 以一份成功的目前使用者回應整批替換能力。回應不合格式時不改狀態並回 false。
 * `gen` 為請求發出當下的世代；與目前不同代表中間發生過登出或換帳號，回應丟棄。
 */
export function applyCurrentUser(info, gen = generation) {
  if (gen !== generation) return false
  if (!isValidProjection(info)) return false
  permissionSet.value = new Set(info.permissions)
  scopeSummary.value = Array.isArray(info.scope_summary) ? info.scope_summary : []
  if (typeof info.product_version === 'string') productVersion.value = info.product_version
  loadedUserId.value = info.id ?? null
  status.value = 'ready'
  return true
}

/**
 * 載入目前使用者能力。守衛與側欄共用同一個在途請求；已有快照且未要求強制重取時直接回傳。
 * 回傳是否處於 ready。失敗：已有同會話快照則保留，否則進入 error（受限入口不放行，可重試）。
 */
export function loadCapabilities({ force = false } = {}) {
  if (inflight) return inflight
  if (!force && status.value === 'ready') return Promise.resolve(true)
  const gen = generation
  if (status.value !== 'ready') status.value = 'loading'
  const run = (async () => {
    await null // 讓 inflight 先被指派，finally 才清得掉
    try {
      const info = unwrap(await getCurrentUser())
      if (gen !== generation) return false
      // 版本行只是顯示用的值，與能力是否合格式無關：缺 permissions 的回應仍可讀出版本
      if (typeof info?.product_version === 'string') productVersion.value = info.product_version
      if (!applyCurrentUser(info, gen)) {
        if (status.value !== 'ready') status.value = 'error'
        return status.value === 'ready'
      }
      return true
    } catch {
      if (gen === generation && status.value !== 'ready') status.value = 'error'
      return gen === generation && status.value === 'ready'
    } finally {
      if (inflight === run) inflight = null
    }
  })()
  inflight = run
  return run
}

/** 清空能力並使在途回應作廢（登出、切換帳號、續期終敗）。 */
export function resetCapabilities() {
  generation += 1
  inflight = null
  permissionSet.value = null
  scopeSummary.value = []
  productVersion.value = ''
  loadedUserId.value = null
  status.value = 'idle'
}

onSessionEnded(resetCapabilities)

/** 測試用：直接寫入已載入的能力。 */
export function setCapabilitiesForTests(perms, { scope = [], userId = null } = {}) {
  generation += 1
  inflight = null
  permissionSet.value = new Set(perms)
  scopeSummary.value = scope
  loadedUserId.value = userId
  status.value = 'ready'
}

export function useCapabilities() {
  return {
    can,
    canAll,
    status,
    ready: computed(() => status.value === 'ready'),
    failed: computed(() => status.value === 'error'),
    scopeSummary,
    productVersion,
    loadedUserId,
    permissions: computed(() => (permissionSet.value ? [...permissionSet.value].sort() : [])),
    load: loadCapabilities,
    reload: () => loadCapabilities({ force: true }),
    reset: resetCapabilities,
  }
}
