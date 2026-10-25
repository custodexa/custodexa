import { onBeforeUnmount, ref } from 'vue'
import { previewRoleAssignment } from '@/api/roleDefinitions'

/**
 * 影響預覽的共用呼叫：防抖加 latest-request-wins。
 *
 * - `schedule(body)`：編輯中使用，延後送出；新的呼叫取代尚未送出的舊呼叫。
 * - `run(body)`：按下儲存時使用，立即送出，回傳 { ok, data }。
 * - 共用狀態（result、status）只接受最後一次發出的請求；較早發出而較晚回來的回應丟棄。
 * - 預覽是建議性的：失敗或無權（403）一律為 ok:false、status 'unavailable'，不丟例外。
 */
export function useAssignmentPreview({ debounceMs = 400 } = {}) {
  const result = ref(null)
  const status = ref('idle') // idle | loading | ok | unavailable
  let seq = 0
  let timer = null

  const clearTimer = () => {
    if (timer) {
      clearTimeout(timer)
      timer = null
    }
  }

  async function run(body) {
    clearTimer()
    const mine = ++seq
    status.value = 'loading'
    let outcome
    try {
      const data = await previewRoleAssignment(body)
      outcome = { ok: true, data }
    } catch {
      outcome = { ok: false, data: null }
    }
    if (mine === seq) {
      result.value = outcome.data
      status.value = outcome.ok ? 'ok' : 'unavailable'
    }
    return outcome
  }

  function schedule(body) {
    clearTimer()
    seq += 1 // 取代任何已在途的請求
    status.value = 'loading'
    timer = setTimeout(() => {
      timer = null
      run(body)
    }, debounceMs)
  }

  function cancel() {
    clearTimer()
    seq += 1
  }

  onBeforeUnmount(cancel)
  return { result, status, run, schedule, cancel }
}
