import { ref, computed, onBeforeUnmount } from 'vue'
import { resolveApiError } from '@/api/error'

/**
 * 審閱面的批次處理：勾選多筆 → 共用理由 → 前端逐筆呼叫既有單筆端點。
 *
 * 非原子：每筆各自一次請求、各自判權、各自留稽核，可能部分完成。
 * 整批帶同一個 batch_id（UUID v4），讓稽核紀錄能把同一次操作串回來。
 *
 * 結果四態：
 *   success      伺服端回 2xx
 *   rejected     伺服端回 4xx（附錯誤碼譯文）
 *   notSent      沒送出（中途離開頁面、或掛載收尾時查得尚未生效）
 *   unconfirmed  送出了但不知道結果（無回應、逾時、5xx）
 * 執行中另有 queued（排隊）與 inflight（已送出等回應）兩個過渡態。
 *
 * 進度逐筆寫入 sessionStorage：頁面在執行中被關掉或重新整理，下次掛載時
 * inflight → unconfirmed、queued → notSent，再請該面提供的查詢函式向伺服端
 * 比對實際狀態。**不自動續送**——使用者按「完成」才清掉紀錄。
 */

export const BATCH_LIMIT = 50

export const BATCH_STATE = Object.freeze({
  QUEUED: 'queued',
  INFLIGHT: 'inflight',
  SUCCESS: 'success',
  REJECTED: 'rejected',
  NOT_SENT: 'notSent',
  UNCONFIRMED: 'unconfirmed',
})

const STORAGE_PREFIX = 'ot-batch-review:'
const STORAGE_VERSION = 1

/**
 * UUID v4。正式環境可能是 http（非安全來源），crypto.randomUUID 不存在，
 * 只用 getRandomValues（在非安全來源仍可用）。
 */
export function generateBatchId() {
  const bytes = new Uint8Array(16)
  globalThis.crypto.getRandomValues(bytes)
  bytes[6] = (bytes[6] & 0x0f) | 0x40
  bytes[8] = (bytes[8] & 0x3f) | 0x80
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

/**
 * 把單筆請求的錯誤歸成四態之一。
 * 4xx＝伺服端明確拒絕；其餘（沒有回應、逾時、5xx）都無法斷定是否已生效，
 * 歸待確認，交給收尾查詢。
 */
export function classifyBatchError(error) {
  const status = error?.response?.status
  if (status >= 400 && status < 500) {
    const data = error.response.data
    return {
      state: BATCH_STATE.REJECTED,
      code: typeof data?.code === 'string' ? data.code : '',
      reason: resolveApiError(data, status),
    }
  }
  return { state: BATCH_STATE.UNCONFIRMED, code: '', reason: '' }
}

function readStorage(key) {
  try {
    const raw = sessionStorage.getItem(key)
    if (!raw) return null
    const parsed = JSON.parse(raw)
    if (parsed?.v !== STORAGE_VERSION || !Array.isArray(parsed.items)) return null
    return parsed
  } catch {
    return null
  }
}

function writeStorage(key, entry) {
  try {
    sessionStorage.setItem(key, JSON.stringify(entry))
  } catch {
    // 儲存空間不可用（隱私模式等）：批次照常執行，只是失去重新整理後的收尾
  }
}

function removeStorage(key) {
  try {
    sessionStorage.removeItem(key)
  } catch {
    // 同上
  }
}

const countBy = (items, state) => items.filter((item) => item.state === state).length

/**
 * @param {Object} options
 * @param {string} options.surface  面代號（alerts / approvals-pending / approvals-reviews），決定儲存鍵
 * @param {import('vue').Ref<number|null>} options.userId  目前使用者；收尾時只接手自己的批次
 * @param {(entry) => Promise<Object<string, {state, reason?, code?, note?}>>} [options.reconcile]
 *   收尾查詢：回傳 { [id]: 新狀態 }，只需涵蓋待確認的項目；拋錯＝維持待確認
 */
export function useBatchReview({ surface, userId, reconcile }) {
  const storageKey = `${STORAGE_PREFIX}${surface}`
  const phase = ref('idle') // idle | running | reconciling | result
  const batch = ref(null)
  const current = ref(0)
  let disposed = false

  const items = computed(() => batch.value?.items || [])
  const total = computed(() => items.value.length)
  const summary = computed(() => ({
    success: countBy(items.value, BATCH_STATE.SUCCESS),
    rejected: countBy(items.value, BATCH_STATE.REJECTED),
    notSent: countBy(items.value, BATCH_STATE.NOT_SENT),
    unconfirmed: countBy(items.value, BATCH_STATE.UNCONFIRMED),
  }))

  const persist = () => {
    if (batch.value) writeStorage(storageKey, batch.value)
  }

  const patchItem = (index, patch) => {
    const list = batch.value.items
    list.splice(index, 1, { ...list[index], ...patch })
    if (!disposed) {
      persist()
      return
    }
    // 已卸載後才回來的回應：重新掛載的實例可能已接手並改寫紀錄，只回寫這一筆
    const saved = readStorage(storageKey)
    if (!saved || saved.batchId !== batch.value.batchId) return
    const id = list[index].id
    writeStorage(storageKey, {
      ...saved,
      items: saved.items.map((item) => (item.id === id ? { ...item, ...patch } : item)),
    })
  }

  const guardUnload = (event) => {
    event.preventDefault()
    event.returnValue = ''
  }

  /**
   * 逐筆循序送出。
   * @param {Object} args
   * @param {string} args.kind    批次種類（alert / approve / reject / review）
   * @param {Object} args.params  共用參數（處置、理由）；收尾比對會用到
   * @param {Array<{id, label, meta?}>} args.entries
   * @param {(entry, batchId) => Promise<{message?, waiting?}|void>} args.send  送出單筆
   */
  async function run({ kind, params, entries, send }) {
    if (phase.value === 'running' || !entries.length) return
    batch.value = {
      v: STORAGE_VERSION,
      batchId: generateBatchId(),
      kind,
      params,
      userId: userId?.value ?? null,
      startedAt: new Date().toISOString(),
      items: entries.map((entry) => ({ ...entry, state: BATCH_STATE.QUEUED, message: '' })),
    }
    phase.value = 'running'
    current.value = 0
    persist()
    window.addEventListener('beforeunload', guardUnload)
    const batchId = batch.value.batchId
    try {
      for (let index = 0; index < batch.value.items.length; index += 1) {
        // 元件已卸載（使用者離開頁面）：剩下的不再送，留 queued 由下次收尾標成未送出
        if (disposed) break
        current.value = index + 1
        patchItem(index, { state: BATCH_STATE.INFLIGHT })
        try {
          const outcome = await send(batch.value.items[index], batchId)
          patchItem(index, { state: BATCH_STATE.SUCCESS, ...(outcome || {}) })
        } catch (error) {
          patchItem(index, classifyBatchError(error))
        }
      }
    } finally {
      window.removeEventListener('beforeunload', guardUnload)
    }
    if (!disposed) phase.value = 'result'
  }

  async function applyReconcile() {
    if (!reconcile || !batch.value) return
    const pending = batch.value.items.filter((item) => item.state === BATCH_STATE.UNCONFIRMED)
    if (!pending.length) return
    let updates = {}
    try {
      updates = (await reconcile(batch.value)) || {}
    } catch {
      return // 查不到：維持待確認
    }
    if (!batch.value) return
    batch.value.items.forEach((item, index) => {
      const update = updates[item.id]
      if (item.state === BATCH_STATE.UNCONFIRMED && update) patchItem(index, update)
    })
  }

  /** 掛載時呼叫：接手未收尾的批次（只接自己的）。回傳是否有批次要顯示 */
  async function recover() {
    const saved = readStorage(storageKey)
    if (!saved) return false
    if ((saved.userId ?? null) !== (userId?.value ?? null)) {
      removeStorage(storageKey)
      return false
    }
    batch.value = {
      ...saved,
      items: saved.items.map((item) => {
        if (item.state === BATCH_STATE.INFLIGHT) return { ...item, state: BATCH_STATE.UNCONFIRMED }
        if (item.state === BATCH_STATE.QUEUED) return { ...item, state: BATCH_STATE.NOT_SENT }
        return item
      }),
    }
    persist()
    phase.value = 'reconciling'
    await applyReconcile()
    if (!disposed) phase.value = 'result'
    return true
  }

  /** 結果畫面「重新查詢」：再比對一次仍待確認的項目 */
  async function recheck() {
    if (phase.value !== 'result') return
    phase.value = 'reconciling'
    await applyReconcile()
    if (!disposed) phase.value = 'result'
  }

  /** 使用者按「完成」：清掉紀錄 */
  function finish() {
    removeStorage(storageKey)
    batch.value = null
    phase.value = 'idle'
    current.value = 0
  }

  onBeforeUnmount(() => {
    disposed = true
    window.removeEventListener('beforeunload', guardUnload)
  })

  return { phase, batch, items, current, total, summary, run, recover, recheck, finish }
}

/**
 * 勾選狀態：以 id 去重、上限 BATCH_LIMIT。「全選」只取本頁可勾者，
 * 達上限即停，並記下是否因上限而少勾。
 */
export function useBatchSelection({ limit = BATCH_LIMIT } = {}) {
  const selected = ref([])
  const truncated = ref(false)
  const selectedIds = computed(() => new Set(selected.value.map((row) => row.id)))
  const atLimit = computed(() => selected.value.length >= limit)

  const isSelected = (row) => selectedIds.value.has(row.id)
  const canToggle = (row, canSelect) =>
    canSelect(row) && (isSelected(row) || !atLimit.value)

  function toggle(row, checked) {
    truncated.value = false
    if (!checked) {
      selected.value = selected.value.filter((item) => item.id !== row.id)
      return
    }
    if (isSelected(row) || atLimit.value) return
    selected.value = [...selected.value, row]
  }

  /** 本頁全選狀態：checked／indeterminate／disabled */
  function pageState(rows, canSelect) {
    const selectable = rows.filter(canSelect)
    const picked = selectable.filter(isSelected).length
    const room = Math.max(0, limit - selected.value.length)
    const full = picked > 0 && (picked === selectable.length || room === 0)
    return {
      checked: full,
      indeterminate: picked > 0 && !full,
      disabled: selectable.length === 0,
    }
  }

  function toggleAll(rows, canSelect) {
    const state = pageState(rows, canSelect)
    if (state.checked) {
      const pageIds = new Set(rows.map((row) => row.id))
      selected.value = selected.value.filter((row) => !pageIds.has(row.id))
      truncated.value = false
      return
    }
    const additions = rows.filter((row) => canSelect(row) && !isSelected(row))
    const room = Math.max(0, limit - selected.value.length)
    selected.value = [...selected.value, ...additions.slice(0, room)]
    truncated.value = additions.length > room
  }

  function clear() {
    selected.value = []
    truncated.value = false
  }

  return { selected, truncated, atLimit, limit, isSelected, canToggle, toggle, toggleAll, pageState, clear }
}
