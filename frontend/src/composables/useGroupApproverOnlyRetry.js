import { ref } from 'vue'
import { groupApproverOnlyDetail } from '@/api/approverOnly'

/**
 * 群組變更被判定為「會讓成員只剩審核者角色」時的重新檢查。
 * run 接一個無參數的送出函式，本文在呼叫端組好後就固定在函式內；
 * 被這個碼拒絕時記下該函式與受影響成員，retry 以同一函式原樣重送，由伺服器重新判定。
 * 其他錯誤原樣拋回呼叫端。草稿變動時呼叫端呼叫 clear，回到一般儲存。
 */
export function useGroupApproverOnlyRetry() {
  const blocked = ref(null)
  const retrying = ref(false)
  let lastSend = null

  const clear = () => {
    blocked.value = null
    lastSend = null
  }

  /** @returns {Promise<{ ok: boolean, res?: any }>} */
  const run = async (send) => {
    try {
      const res = await send()
      clear()
      return { ok: true, res }
    } catch (error) {
      const detail = groupApproverOnlyDetail(error)
      if (!detail) throw error
      blocked.value = detail
      lastSend = send
      return { ok: false }
    }
  }

  /** 以上一次被拒的同一份本文重送；沒有可重送的請求時回 null */
  const retry = async () => {
    if (!lastSend || retrying.value) return null
    retrying.value = true
    try {
      return await run(lastSend)
    } finally {
      retrying.value = false
    }
  }

  return { blocked, retrying, run, retry, clear }
}
