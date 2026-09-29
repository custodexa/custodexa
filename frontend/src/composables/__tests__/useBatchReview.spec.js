import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  BATCH_LIMIT,
  generateBatchId,
  classifyBatchError,
  useBatchSelection,
} from '../useBatchReview'

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

describe('generateBatchId', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('以 getRandomValues 產生 UUID v4，不依賴 crypto.randomUUID', () => {
    const getRandomValues = vi.fn((bytes) => {
      for (let i = 0; i < bytes.length; i += 1) bytes[i] = (i * 37 + 11) & 0xff
      return bytes
    })
    // 非安全來源（http）下沒有 randomUUID：只給 getRandomValues
    vi.stubGlobal('crypto', { getRandomValues })
    const id = generateBatchId()
    expect(getRandomValues).toHaveBeenCalledTimes(1)
    expect(id).toMatch(UUID_V4)
  })

  it('連續產生的值不重複', () => {
    const ids = new Set(Array.from({ length: 20 }, () => generateBatchId()))
    expect(ids.size).toBe(20)
    for (const id of ids) expect(id).toMatch(UUID_V4)
  })
})

describe('classifyBatchError', () => {
  it('4xx 為被拒並帶錯誤碼譯文', () => {
    const out = classifyBatchError({
      response: { status: 409, data: { code: 'CONFLICT_ALERT_ALREADY_REVIEWED', error: 'x' } },
    })
    expect(out.state).toBe('rejected')
    expect(out.code).toBe('CONFLICT_ALERT_ALREADY_REVIEWED')
    expect(out.reason).toBe('送出時已有審閱結果')
  })

  it('無回應、逾時與 502/503/504 為待確認', () => {
    expect(classifyBatchError({ request: {} }).state).toBe('unconfirmed')
    expect(classifyBatchError({ code: 'ECONNABORTED', request: {} }).state).toBe('unconfirmed')
    for (const status of [502, 503, 504]) {
      expect(classifyBatchError({ response: { status, data: {} } }).state).toBe('unconfirmed')
    }
  })
})

describe('useBatchSelection', () => {
  let selection
  const canSelect = (row) => !row.locked
  beforeEach(() => {
    selection = useBatchSelection()
  })

  it('同一 id 重複勾選只算一筆', () => {
    selection.toggle({ id: 1 }, true)
    selection.toggle({ id: 1 }, true)
    expect(selection.selected.value.map((r) => r.id)).toEqual([1])
  })

  it(`全選只取可勾者，且最多 ${BATCH_LIMIT} 筆；達上限後不可再勾`, () => {
    const rows = Array.from({ length: BATCH_LIMIT + 5 }, (_, i) => ({ id: i + 1, locked: i === 0 }))
    selection.toggleAll(rows, canSelect)
    expect(selection.selected.value).toHaveLength(BATCH_LIMIT)
    expect(selection.selected.value.some((r) => r.id === 1)).toBe(false)
    expect(selection.atLimit.value).toBe(true)
    const outside = rows.find((r) => !selection.isSelected(r) && canSelect(r))
    expect(selection.canToggle(outside, canSelect)).toBe(false)
    selection.toggle(outside, true)
    expect(selection.selected.value).toHaveLength(BATCH_LIMIT)
  })
})
