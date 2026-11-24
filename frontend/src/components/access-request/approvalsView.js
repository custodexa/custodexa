import { t } from '@/i18n'
import { can } from '@/composables/useCapabilities'
import { formatMinutes } from '@/components/batch-review/accessRequestBatch'

/**
 * 審核中心待審單的呈現判讀：只讀待審回應帶回的欄位，不另外查詢。
 * 這裡的判斷只決定畫面上給不給入口；能不能核決一律由後端在受理請求時判定。
 */

export { formatMinutes }

// 站內的「看這張申請單」：記下這次是從站內點進去的，直達頁就不標示成從通知連結進來
const INTERNAL_KEY = 'ot-approvals-internal-request'
export function markInternalNav(id) {
  try { sessionStorage.setItem(INTERNAL_KEY, String(id)) } catch { /* 無法保存時照常前往 */ }
}
/** 讀取並清掉站內點擊的記號：與網址上的單號相同才算站內進入 */
export function consumeInternalNav(id) {
  try {
    const value = sessionStorage.getItem(INTERNAL_KEY)
    sessionStorage.removeItem(INTERNAL_KEY)
    return id != null && value === String(id)
  } catch {
    return false
  }
}

export const requesterName = (req) => req?.requester?.username || `#${req?.requester_id}`

/** 「看這張申請單」：持 audit:view 者進任務視角，其餘審核者落在審核中心歷史頁的這張單 */
export const requestHref = (id) => (can('audit:view')
  ? `/audit/agent-tasks/${id}`
  : `/approvals?tab=history&request=${id}`)

/** 項目的資產名稱：取待審回應隨項目帶回的名稱；為空時明說無法讀取並保留識別碼 */
export function itemAssetName(item) {
  if (item?.asset_name) return item.asset_name
  return t('itemReview.assetNameUnreadable', { id: item?.asset_id })
}

export function accountsText(accounts) {
  const list = Array.isArray(accounts) ? accounts : []
  return list.length && !list.includes('@ALL')
    ? list.join(t('common.listSeparator'))
    : t('multiRequest.allAccounts')
}

export const itemAccounts = (item) => item?.requested_accounts || item?.accounts

export const pendingItems = (req) => (req?.items || []).filter((item) => item.status === 'pending')

const votedBy = (item, me) => me != null && (item?.approvals || []).some((vote) => vote.approver_id === me)

/** 這一項我已投過核准票（還在等其他審核人） */
export const itemVotedByMe = (item, me) => item?.status === 'pending' && votedBy(item, me)

/** 還在等這位審核人決定的項目：待審且這位審核人還沒投票 */
export const itemsAwaiting = (req, me) => pendingItems(req).filter((item) => !votedBy(item, me))

/** 這張還有沒有等這位審核人決定的項目（舊式無項目單以整張的票判斷） */
export function awaitsMe(req, me) {
  if (!req?.items?.length) {
    return !(req?.approvals || []).some((vote) => vote.approver_id === me)
  }
  return itemsAwaiting(req, me).length > 0
}

/** 我是否投過這張的核准票（核准進度欄的「你已核准」） */
export const approvedByMe = (req, me) => me != null && (
  (req?.approvals || []).some((vote) => vote.approver_id === me)
  || pendingItems(req).some((item) => votedBy(item, me))
)

/** 門檻：取待決項目的最大門檻，沒有時用整張的 */
export function requiredOf(req) {
  const fromItems = pendingItems(req).map((item) => item.approvals_required || 0)
  return Math.max(req?.approvals_required || 1, ...fromItems, 1)
}

/** 已核准的不同審核人（以人計，不以票計） */
export function approversOf(req) {
  const seen = new Map()
  const add = (vote) => {
    if (vote?.approver_id == null || seen.has(vote.approver_id)) return
    seen.set(vote.approver_id, vote.approver?.username || `#${vote.approver_id}`)
  }
  ;(req?.approvals || []).forEach(add)
  pendingItems(req).forEach((item) => (item.approvals || []).forEach(add))
  return [...seen.entries()].map(([id, name]) => ({ id, name }))
}

/**
 * 整張核准的門檻說明：只看這次會送出的項（等候這位審核人決定的項），
 * 已核准的人排除這位審核人自己；各項門檻不同時取最壞情況（還要最多人的那一項）。
 * 回傳 { required, names, left }，left 是這次核准後仍需的人數；不需多位審核人時回傳 null。
 */
export function thresholdFor(req, me) {
  const items = req?.items?.length ? itemsAwaiting(req, me) : null
  const votesOf = (votes) => (votes || []).filter((vote) => vote?.approver_id != null && vote.approver_id !== me)
  const groups = items
    ? items.map((item) => ({ required: item.approvals_required || req.approvals_required || 1, votes: votesOf(item.approvals) }))
    : [{ required: req?.approvals_required || 1, votes: votesOf(req?.approvals) }]
  if (!groups.length) return null
  const required = Math.max(1, ...groups.map((g) => g.required))
  if (required <= 1) return null
  const names = new Map()
  let left = 0
  for (const g of groups) {
    const people = new Set(g.votes.map((vote) => vote.approver_id))
    g.votes.forEach((vote) => names.set(vote.approver_id, vote.approver?.username || `#${vote.approver_id}`))
    left = Math.max(left, g.required - people.size - 1)
  }
  return { required, names: [...names.values()], left: Math.max(0, left) }
}

/** 已投票者還要等幾位：門檻減去已核准的人數 */
export const othersNeeded = (req) => Math.max(0, requiredOf(req) - approversOf(req).length)

/** 單號下方與資產欄用的資產名稱清單（多項取每一項的名稱，舊式單用單頭資產） */
export function assetNames(req) {
  if (req?.items?.length) return req.items.map(itemAssetName)
  return [req?.asset?.name || t('common.assetRef', { id: req?.asset_id })]
}

export const assetCount = (req) => (req?.items?.length || 1)

/** 「web-prod-03」或「db-stg-02 等 2 台」 */
export function assetSummary(req) {
  const names = assetNames(req)
  if (names.length <= 1) return names[0] || ''
  return t('approvals.done.assetMany', { first: names[0], n: names.length, m: names.length - 1 })
}
