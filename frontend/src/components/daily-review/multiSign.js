import { getDailyReviewPending } from '@/api/dailyReviews'
import { clearBatchProgress } from '@/composables/useBatchReview'
import { onSessionEnded } from '@/utils/session'

// 每日簽核的多日簽核：勾選多個待簽日，前端逐日呼叫既有的單日簽核端點。
// 能不能簽仍由伺服器逐日判定；這裡的規則只決定介面上能不能勾選。

/** 批次進度在分頁暫存裡的面代號（useBatchReview 的 surface） */
export const MULTI_SIGN_SURFACE = 'daily-review'

/** 待簽清單每頁天數（與後端每頁上限相同） */
export const PENDING_PAGE_SIZE = 31

// 會話結束（登出、續期終敗、他分頁登出）時清掉批次進度：延遲原因、備註與逐日結果
// 不留給同一個分頁的下一位使用者。模組層註冊，由常駐的側欄徽章模組引入，
// 不依賴每日簽核頁面是否開著。
onSessionEnded(() => clearBatchProgress(MULTI_SIGN_SURFACE))

/** 列的識別：待簽日沒有 id，以所屬日為識別 */
export const dayKey = (row) => row.date

/** 待簽日還有幾筆未審閱告警（來源已清除時為 0：查不到的告警不擋，與單日相同） */
export const pendingAlertCount = (row) => {
  const n = row?.counts?.unreviewed_alerts
  return typeof n === 'number' && n > 0 ? n : 0
}

/**
 * 待簽清單上能不能勾選：只看可不可簽（已過落庫寬限）。有未審閱告警的日子也可以勾：
 * 勾了先一起處置告警，處置完才進簽核。不因來源不明多加限制。
 */
export const isDaySelectable = (row) => row?.signable === true

/**
 * 能不能進入多日簽核的確認：可簽且沒有未審閱告警。規則與單日抽屜相同，伺服器仍逐日再檢查一次。
 */
export const isDaySignable = (row) => isDaySelectable(row) && pendingAlertCount(row) === 0

/**
 * 重新取得所選日子目前在待簽清單上的資料（開啟確認步驟時）。
 * 待簽清單由最早排起：逐頁往後讀，所選的日子都找到、或已讀過最晚的所選日就停。
 * 回傳 Map<date, row>；不在其中的日子表示已不在待簽清單（已被簽核等）。
 */
export async function fetchPendingDays(dates) {
  const wanted = new Set(dates)
  const latest = [...wanted].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)).pop() || ''
  const found = new Map()
  for (let page = 1; wanted.size > found.size; page += 1) {
    const res = await getDailyReviewPending({ page, page_size: PENDING_PAGE_SIZE }, { skipErrorToast: true })
    const items = res?.data?.items || []
    for (const item of items) {
      if (wanted.has(item.date)) found.set(item.date, item)
    }
    const total = Number(res?.data?.total) || 0
    const last = items[items.length - 1]?.date || ''
    if (!items.length || page * PENDING_PAGE_SIZE >= total || last >= latest) break
  }
  return found
}

// 確認對話框的版面：逐日清單在框內捲動（表頭固定），清單以外的部分（說明、延遲原因、
// 備註、按鈕）要整個留在視窗內。清單高度＝視窗高度扣掉上下留白與清單以外的高度，
// 夾在下限與上限之間；視窗矮到連下限都放不下時才讓整個遮罩捲動
export const CONFIRM_LIST_MAX_HEIGHT = 320
export const CONFIRM_LIST_MIN_HEIGHT = 120
export const CONFIRM_DIALOG_GAP = 24

export function fitListHeight({
  viewport, dialogHeight, listHeight,
  gap = CONFIRM_DIALOG_GAP, min = CONFIRM_LIST_MIN_HEIGHT, max = CONFIRM_LIST_MAX_HEIGHT,
}) {
  const others = Math.max(0, dialogHeight - listHeight)
  const room = Math.floor(viewport - gap * 2 - others)
  return Math.max(min, Math.min(max, room))
}
