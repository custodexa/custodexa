import { t } from '@/i18n'

/**
 * 審核中心批次處理的純函式：核准回應判讀、收尾比對、被拒原因措辭。
 * 與元件分開，讓待審與待補審兩個對話框共用同一套判準。
 */

export const requesterName = (req) => req.requester?.username || `#${req.requester_id}`

export function formatMinutes(minutes) {
  if (!minutes && minutes !== 0) return '—'
  if (minutes < 60) return t('common.minutesN', { n: minutes })
  const hours = Math.floor(minutes / 60)
  const rest = minutes % 60
  return rest === 0
    ? t('common.hoursN', { n: hours })
    : t('common.hoursMinutes', { h: hours, m: rest })
}

/**
 * 核准回應 → 這一張的成功樣態：
 *   approved  所選項目都已生效
 *   voted     所選項目都仍待決（已投票、等其他審核人），附票數與門檻（回應有才附）
 *   partly    部分項目生效、部分仍待決
 * waiting＝仍需其他審核人，供摘要的「其中 N 張仍需其他審核人」。
 */
export function approveOutcome(res, meta = {}) {
  const itemIds = meta.itemIds || []
  if (meta.hasItems && Array.isArray(res?.items)) {
    const picked = res.items.filter((item) => itemIds.includes(item.id))
    const waiting = picked.filter((item) => item.status === 'pending')
    if (!picked.length || !waiting.length) return { outcome: { kind: 'approved' }, waiting: false }
    if (waiting.length < picked.length) {
      return {
        outcome: { kind: 'partly', approved: picked.length - waiting.length, pending: waiting.length },
        waiting: true,
      }
    }
    const [first] = waiting
    const uniform = waiting.every((item) =>
      item.approvals_received === first.approvals_received
      && item.approvals_required === first.approvals_required)
    const hasQuorum = uniform && first.approvals_required > 0
    return {
      outcome: hasQuorum
        ? { kind: 'voted', received: first.approvals_received, required: first.approvals_required }
        : { kind: 'voted' },
      waiting: true,
    }
  }
  if (res?.status === 'pending') {
    return {
      outcome: res.approvals_required > 0
        ? { kind: 'voted', received: res.approvals_received, required: res.approvals_required }
        : { kind: 'voted' },
      waiting: true,
    }
  }
  return { outcome: { kind: 'approved' }, waiting: false }
}

/** 這張單上所選項目是否都已有我的票（或已由我決定） */
export function hasMyVotes(row, itemIds, me) {
  if (me == null) return false
  const votedBy = (votes) => (votes || []).some((vote) => vote.approver_id === me)
  if (itemIds.length) {
    return itemIds.every((itemId) => {
      const item = (row.items || []).find((candidate) => candidate.id === itemId)
      return !!item && (votedBy(item.approvals) || item.decided_by === me)
    })
  }
  return votedBy(row.approvals)
}

/** 已離開待審的單：是否由我做出與這一批相同方向的決定 */
export function decidedByMe(row, kind, me) {
  if (me == null) return false
  const items = row.items || []
  if (kind === 'reject') {
    return (row.status === 'rejected' && row.approver_id === me)
      || items.some((item) => item.status === 'rejected' && item.decided_by === me)
  }
  return (row.approvals || []).some((vote) => vote.approver_id === me)
    || items.some((item) => item.status === 'approved' && item.decided_by === me)
    || (row.status === 'approved' && row.approver_id === me)
}

// 批次情境下需要比單筆 toast 多講一句的錯誤碼：範圍外要說清楚整張沒生效；
// 自核要涵蓋「自己執行」的單
const BATCH_REASON_KEYS = {
  RULE_ACCESS_REQUEST_NOT_ELIGIBLE_APPROVER: 'approvals.batch.notEligible',
  RULE_ACCESS_REQUEST_SELF_APPROVAL: 'approvals.batch.selfApproval',
}

export function batchRejectReason(item) {
  const key = BATCH_REASON_KEYS[item.code]
  return key ? t(key) : item.reason || ''
}
