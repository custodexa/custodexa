import { describe, it, expect } from 'vitest'
import { historyVerdict, hasMyVotes } from '../accessRequestBatch'

// 已離開待審的單：只以這一次送出的項目判定這一次的決定有沒有生效
const ME = 67
const OTHER = 99

const item = (id, extra = {}) => ({ id, status: 'pending', ...extra })

describe('historyVerdict：核准', () => {
  it('同單另一項先前由本人核准、這一次送出的項目被別人拒絕：不算這一次生效', () => {
    const row = {
      id: 201,
      status: 'rejected',
      approvals: [{ approver_id: ME, item_id: 1 }],
      items: [
        item(1, { status: 'approved', decided_by: ME }),
        item(2, { status: 'rejected', decided_by: OTHER }),
      ],
    }
    expect(historyVerdict(row, 'approve', [2], ME)).toBe('others')
  })

  it('這一次送出的項目確實由本人核准：生效', () => {
    const row = {
      status: 'approved',
      approver_id: ME,
      items: [item(1, { status: 'approved', decided_by: OTHER }), item(2, { status: 'approved', decided_by: ME })],
    }
    expect(historyVerdict(row, 'approve', [2], ME)).toBe('mine')
  })

  it('這一次送出的項目被別人拒絕、沒有本人的票：沒有生效', () => {
    const row = { status: 'rejected', items: [item(2, { status: 'rejected', decided_by: OTHER })] }
    expect(historyVerdict(row, 'approve', [2], ME)).toBe('others')
  })

  it('多人門檻：本人的票已記入、由另一位補齊門檻而核准：生效', () => {
    const row = {
      status: 'approved',
      approver_id: OTHER,
      approvals: [{ approver_id: ME, item_id: 2 }, { approver_id: OTHER, item_id: 2 }],
      items: [item(2, { status: 'approved', decided_by: OTHER })],
    }
    expect(historyVerdict(row, 'approve', [2], ME)).toBe('mine')
  })

  it('多人門檻：本人的票已記入但未達門檻，之後單子結束：資料不足，維持待確認', () => {
    const expired = {
      status: 'expired',
      approvals: [{ approver_id: ME, item_id: 2 }],
      items: [item(2, { status: 'revoked' })],
    }
    expect(historyVerdict(expired, 'approve', [2], ME)).toBe('unknown')
    const rejected = {
      status: 'rejected',
      approvals: [{ approver_id: ME, item_id: 2 }],
      items: [item(2, { status: 'rejected', decided_by: OTHER })],
    }
    expect(historyVerdict(rejected, 'approve', [2], ME)).toBe('unknown')
  })

  it('核准後被撤銷的項目仍以決定者判定', () => {
    const row = { status: 'approved', items: [item(2, { status: 'revoked', decided_by: ME })] }
    expect(historyVerdict(row, 'approve', [2], ME)).toBe('mine')
  })

  it('送出兩項、一項有本人決定一項沒有：結果不一致，維持待確認', () => {
    const row = {
      status: 'rejected',
      items: [item(2, { status: 'approved', decided_by: ME }), item(3, { status: 'rejected', decided_by: OTHER })],
    }
    expect(historyVerdict(row, 'approve', [2, 3], ME)).toBe('unknown')
  })

  it('送出的項目不在查回的資料裡：維持待確認', () => {
    const row = { status: 'approved', items: [item(1, { status: 'approved', decided_by: ME })] }
    expect(historyVerdict(row, 'approve', [2], ME)).toBe('unknown')
  })

  it('有項目的單卻不知道這一次送了哪幾項：不用其他項目的結果判定', () => {
    const row = { status: 'approved', approver_id: ME, items: [item(1, { status: 'approved', decided_by: ME })] }
    expect(historyVerdict(row, 'approve', [], ME)).toBe('unknown')
  })

  it('分不出投給哪一項的本人票：不拿來判定沒有生效', () => {
    const row = {
      status: 'rejected',
      approvals: [{ approver_id: ME }],
      items: [item(2, { status: 'rejected', decided_by: OTHER })],
    }
    expect(historyVerdict(row, 'approve', [2], ME)).toBe('unknown')
  })

  it('沒有項目的舊式單：以單頭的核准人與票判定', () => {
    expect(historyVerdict({ status: 'approved', approver_id: ME }, 'approve', [], ME)).toBe('mine')
    expect(historyVerdict({ status: 'approved', approver_id: OTHER, approvals: [{ approver_id: ME }] }, 'approve', [], ME)).toBe('mine')
    expect(historyVerdict({ status: 'approved', approver_id: OTHER }, 'approve', [], ME)).toBe('others')
    expect(historyVerdict({ status: 'rejected', approvals: [{ approver_id: ME }] }, 'approve', [], ME)).toBe('unknown')
  })

  it('不知道目前使用者：無從判定', () => {
    expect(historyVerdict({ status: 'approved', approver_id: ME }, 'approve', [], null)).toBe('unknown')
  })
})

describe('historyVerdict：拒絕', () => {
  it('同單另一項先前由本人拒絕、這一次送出的項目由別人核准：不算這一次生效', () => {
    const row = {
      status: 'approved',
      approver_id: OTHER,
      items: [
        item(1, { status: 'rejected', decided_by: ME }),
        item(2, { status: 'approved', decided_by: OTHER }),
      ],
    }
    expect(historyVerdict(row, 'reject', [2], ME)).toBe('others')
  })

  it('這一次送出的項目都由本人拒絕：生效', () => {
    const row = {
      status: 'rejected',
      approver_id: ME,
      items: [item(1, { status: 'approved', decided_by: OTHER }), item(2, { status: 'rejected', decided_by: ME }), item(3, { status: 'rejected', decided_by: ME })],
    }
    expect(historyVerdict(row, 'reject', [2, 3], ME)).toBe('mine')
  })

  it('這一次送出的項目被別人拒絕：沒有生效', () => {
    const row = { status: 'rejected', approver_id: OTHER, items: [item(2, { status: 'rejected', decided_by: OTHER })] }
    expect(historyVerdict(row, 'reject', [2], ME)).toBe('others')
  })

  it('送出兩項、只有一項由本人拒絕：結果不一致，維持待確認', () => {
    const row = {
      status: 'approved',
      items: [item(2, { status: 'rejected', decided_by: ME }), item(3, { status: 'approved', decided_by: OTHER })],
    }
    expect(historyVerdict(row, 'reject', [2, 3], ME)).toBe('unknown')
  })

  it('有項目的單卻不知道這一次涵蓋哪幾項：維持待確認', () => {
    const row = { status: 'rejected', approver_id: ME, items: [item(1, { status: 'rejected', decided_by: ME })] }
    expect(historyVerdict(row, 'reject', [], ME)).toBe('unknown')
  })

  it('沒有項目的舊式單：以單頭的決定者判定', () => {
    expect(historyVerdict({ status: 'rejected', approver_id: ME }, 'reject', [], ME)).toBe('mine')
    expect(historyVerdict({ status: 'rejected', approver_id: OTHER }, 'reject', [], ME)).toBe('others')
    expect(historyVerdict({ status: 'approved', approver_id: ME }, 'reject', [], ME)).toBe('others')
  })
})

describe('hasMyVotes：仍在待審的單', () => {
  it('多人門檻：這一次送出的項目已有本人的票、尚未達門檻：算已記入', () => {
    const row = { status: 'pending', items: [item(1), item(2, { approvals: [{ approver_id: ME }] })] }
    expect(hasMyVotes(row, [2], ME)).toBe(true)
  })

  it('只有其他項目有本人的票：不算這一次已記入', () => {
    const row = { status: 'pending', items: [item(1, { approvals: [{ approver_id: ME }] }), item(2)] }
    expect(hasMyVotes(row, [2], ME)).toBe(false)
  })
})
