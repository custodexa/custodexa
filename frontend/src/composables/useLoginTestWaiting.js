// 登入測試的結果等待。
//
// 登入稽核是非同步寫入，測試者登入後要過幾秒才查得到新紀錄；管理者若很快切回，
// 切回當下抓到的仍是上一次嘗試。複製過測試連結（arm）之後，切回本頁時若最近一次嘗試
// 還是切走前看到的那一筆，就每 2 秒重抓、最多約 15 秒，逾時改說「沒有收到這次登入的紀錄」，
// 並解除，不會無限輪詢。
//
// 「較新」以伺服器時間互比（切走前看到的那一筆對現在這一筆），不拿瀏覽器時鐘比，
// 兩邊時鐘有偏差時也不會誤判。
import { ref } from 'vue'

export const WAIT_POLL_MS = 2000
export const WAIT_MAX_MS = 15000

const attemptAt = (status) => {
  const n = Date.parse(status?.last_attempt?.at || '')
  return Number.isNaN(n) ? null : n
}

/**
 * @param {object} opts
 * @param {() => Promise<void>} opts.fetch 重抓狀態彙總
 * @param {() => object|null} opts.current 目前的狀態彙總
 * @param {() => number} [opts.now]
 */
export function useLoginTestWaiting({ fetch, current, now = () => Date.now() }) {
  // ''：不在等待；waiting：等待中；timeout：等過了仍沒有新紀錄
  const state = ref('')
  let armed = false
  let baseline = null
  let deadline = 0
  let timer = null
  // 每次重設或重新開始都換代，舊的輪詢回來時自行結束
  let gen = 0

  const isNewer = () => {
    const at = attemptAt(current())
    return at !== null && (baseline === null || at > baseline)
  }

  const stopTimer = () => {
    clearTimeout(timer)
    timer = null
  }

  const reset = () => {
    gen++
    stopTimer()
    armed = false
    baseline = null
    state.value = ''
  }

  /** 複製測試連結時呼叫：記下目前看到的最近一次嘗試 */
  const arm = () => {
    reset()
    armed = true
    baseline = attemptAt(current())
  }

  const poll = async (mine) => {
    timer = null
    await fetch()
    if (mine !== gen) return
    if (isNewer()) {
      baseline = attemptAt(current())
      state.value = ''
      return
    }
    if (now() >= deadline) {
      armed = false
      state.value = 'timeout'
      return
    }
    timer = setTimeout(() => poll(mine), WAIT_POLL_MS)
  }

  /** 切回本頁時呼叫；回傳 true 表示由這裡接手，呼叫端不必再做一般的自動重抓 */
  const onReturn = () => {
    if (!armed) return false
    if (state.value === 'waiting') return true
    state.value = 'waiting'
    deadline = now() + WAIT_MAX_MS
    poll(gen)
    return true
  }

  /** 每次狀態更新後呼叫：逾時之後若等到了新紀錄，收掉逾時說明 */
  const observe = () => {
    if (state.value === 'timeout' && isNewer()) state.value = ''
  }

  return { state, arm, reset, onReturn, observe }
}
