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

/**
 * 已離開待審的單：這一次送出的決定有沒有生效。只看這一次送出的項目（itemIds），
 * 同一張單其他項目的舊決定不算數。
 *   mine     送出的項目都由我做出同方向的決定（核准含多人門檻下我的票已記入且已核准）
 *   others   送出的項目都沒有我的這個決定：這一次沒有生效
 *   unknown  資料不足或各項結果不一致：維持待確認
 * 票與決定者不會事後消失，所以「沒有我的票也不是我決定」可以判定這一次沒有送達。
 */
export function historyVerdict(row, kind, itemIds, me) {
  if (me == null || !row) return 'unknown'
  const items = row.items || []
  const votes = row.approvals || []
  const ids = itemIds || []
  if (!ids.length) {
    // 沒有項目的舊式單才以單頭判定；有項目卻不知道送了哪幾項，無從判定
    if (items.length) return 'unknown'
    if (kind === 'reject') {
      return row.status === 'rejected' && row.approver_id === me ? 'mine' : 'others'
    }
    const voted = votes.some((vote) => vote.approver_id === me)
    if (row.status === 'approved' && (voted || row.approver_id === me)) return 'mine'
    return voted ? 'unknown' : 'others'
  }
  // 不屬於任何項目的本人票：分不出是投給哪一項，不拿來否定
  const looseVote = votes.some((vote) => vote.approver_id === me && vote.item_id == null)
  const verdicts = ids.map((itemId) => {
    const item = items.find((candidate) => candidate.id === itemId)
    if (!item) return 'unknown'
    if (kind === 'reject') {
      return item.status === 'rejected' && item.decided_by === me ? 'mine' : 'others'
    }
    const voted = (item.approvals || []).some((vote) => vote.approver_id === me)
      || votes.some((vote) => vote.approver_id === me && vote.item_id === itemId)
    const byMe = voted || item.decided_by === me
    // 核准過的項目：仍為已核准，或核准後被撤銷（撤銷不清除決定者；未決定就結束的項目沒有決定者）
    const approved = item.status === 'approved' || (item.status === 'revoked' && item.decided_by != null)
    if (byMe) return approved ? 'mine' : 'unknown'
    return looseVote ? 'unknown' : 'others'
  })
  if (verdicts.every((verdict) => verdict === 'mine')) return 'mine'
  if (verdicts.every((verdict) => verdict === 'others')) return 'others'
  return 'unknown'
}

// 批次情境下需要比單筆 toast 多講一句的錯誤碼：範圍外要說清楚整張沒生效；
// 自核要涵蓋「自己執行」的單
const BATCH_REASON_KEYS = {
  RULE_ACCESS_REQUEST_NOT_ELIGIBLE_APPROVER: 'approvals.batch.notEligible',
  RULE_ACCESS_REQUEST_SELF_APPROVAL: 'approvals.batch.selfApproval',
  RULE_ACCESS_REQUEST_CONNECT_REQUIRED: 'approvals.batch.connectRequired',
}

export function batchRejectReason(item) {
  const key = BATCH_REASON_KEYS[item.code]
  return key ? t(key) : item.reason || ''
}
