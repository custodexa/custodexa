import { ref } from 'vue'
import { getDailyReviewStatus } from '@/api/dailyReviews'

// 業務時區的分界資訊（目前生效、今天、待生效變更）一律取自後端 /daily-reviews/status 的
// timezone_state。政策頁的欄位說明、儲存前確認框與儲存後的分界句共用這一份，
// 不以政策列的現值或本機日期推算——重新整理或換一台電腦看都要一樣
const state = ref(null)
const loading = ref(false)

async function load() {
  loading.value = true
  try {
    const res = await getDailyReviewStatus({ skipErrorToast: true })
    state.value = res?.data?.timezone_state || null
  } catch {
    // 讀不到時欄位仍可設定，只是不顯示分界說明
    state.value = null
  } finally {
    loading.value = false
  }
}

export function useTimezoneState() {
  return { state, loading, load }
}

// 時區選項：瀏覽器清單 ∪ {UTC} ∪ {後端目前的設定值與生效值}。
// 瀏覽器清單不含 UTC，而 UTC 是後端的預設；後端目前值不在清單時也要照實列出，
// 不能因此顯示空白或被替換。名稱是否合法以後端驗證為準
export function timezoneOptions(extra = []) {
  let names = []
  try {
    names = typeof Intl.supportedValuesOf === 'function' ? Intl.supportedValuesOf('timeZone') : []
  } catch {
    names = []
  }
  const set = new Set(['UTC', ...names])
  for (const name of extra) if (name) set.add(name)
  return [...set]
}
