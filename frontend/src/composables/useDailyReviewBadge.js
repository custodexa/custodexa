import { ref } from 'vue'
import { getDailyReviewPendingCount } from '@/api/dailyReviews'
import { DAILY_REVIEWS_CHANGED } from '@/components/daily-review/dailyReviewFormat'

// 每日簽核的待簽天數徽章（側欄「操作日誌」與每日簽核分頁標籤共用同一份數字）。
//
// 模組層單例：側欄負責輪詢，分頁標籤只讀；兩處各打一次會讓同一個數字在畫面上
// 短暫不一致，也多一倍審計讀取列。輪詢只對具簽核權限者啟動（呼叫端判定），
// 失敗靜默——徽章是提示不是事實源，下一輪自然重試
export const DAILY_REVIEW_BADGE_POLL_MS = 30000

const count = ref(0)
const overdueCount = ref(0)
let timer = null
let listening = false

async function refresh() {
  try {
    const res = await getDailyReviewPendingCount({ skipErrorToast: true })
    count.value = Number(res?.data?.count) || 0
    overdueCount.value = Number(res?.data?.overdue_count) || 0
  } catch {
    // 靜默：403（撤權殘窗）／網路抖動不打擾使用者
  }
}

const onChanged = () => {
  if (timer) void refresh()
}

function start() {
  if (timer) return
  void refresh()
  timer = setInterval(refresh, DAILY_REVIEW_BADGE_POLL_MS)
  if (!listening) {
    window.addEventListener(DAILY_REVIEWS_CHANGED, onChanged)
    listening = true
  }
}

function stop() {
  if (timer) clearInterval(timer)
  timer = null
  if (listening) {
    window.removeEventListener(DAILY_REVIEWS_CHANGED, onChanged)
    listening = false
  }
  count.value = 0
  overdueCount.value = 0
}

export function useDailyReviewBadge() {
  return { count, overdueCount, start, stop, refresh }
}
