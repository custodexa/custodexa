import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import { defineComponent, h, ref } from 'vue'
import {
  BATCH_LIMIT,
  BATCH_STATE,
  BULK_OUTCOME,
  generateBatchId,
  classifyBatchError,
  useBatchReview,
  useBatchSelection,
} from '../useBatchReview'
import { batchReviewAlerts, searchAlerts } from '@/api/alerts'
import {
  NOT_APPLIED_REASON,
  isDefiniteBulkFailure,
  itemPatch,
  reconcileAlertBulk,
} from '@/components/batch-review/alertBulk'

// 替身端點：攔下所有請求（不打任何真實服務），記錄請求設定
const requestMock = vi.fn()
vi.mock('@/api/request', () => ({ default: (...args) => requestMock(...args) }))

enableAutoUnmount(afterEach)

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

  it('keyOf 指定識別：沒有 id 的列以指定欄去重、全選取消只清本頁', () => {
    const sel = useBatchSelection({ keyOf: (row) => row.date })
    sel.toggle({ date: '2026-10-04' }, true)
    sel.toggle({ date: '2026-10-04', counts: {} }, true) // 重取後的新物件仍是同一天
    expect(sel.selected.value).toHaveLength(1)
    expect(sel.isSelected({ date: '2026-10-04' })).toBe(true)
    const page = [{ date: '2026-10-05' }, { date: '2026-10-06' }]
    sel.toggleAll(page, () => true)
    expect(sel.selected.value.map((r) => r.date)).toEqual(['2026-10-04', '2026-10-05', '2026-10-06'])
    sel.toggleAll(page, () => true)
    expect(sel.selected.value.map((r) => r.date)).toEqual(['2026-10-04'])
    sel.toggle({ date: '2026-10-04' }, false)
    expect(sel.selected.value).toHaveLength(0)
  })
})

describe('一次送出的批次', () => {
  const ME = 7
  const SURFACE = 'bulk-spec'
  const KEY = `ot-batch-review:${SURFACE}`
  let clock

  // 使用一次送出模式的最小頁面：送出整批、查回以 id 清單分段
  const Harness = defineComponent({
    props: { entries: { type: Array, default: () => [] } },
    setup(props, { expose }) {
      const userId = ref(ME)
      const reconcile = (entry) => reconcileAlertBulk(entry, { search: searchAlerts, now: () => clock })
      const api = useBatchReview({ surface: SURFACE, userId, reconcile })
      const outcome = ref('')
      const submit = async () => {
        const res = await api.runBulk({
          kind: 'alert-bulk',
          params: { disposition: 'benign', note: '依變更單處置' },
          entries: props.entries,
          isDefiniteFailure: isDefiniteBulkFailure,
          send: async (items, batchId) => {
            const body = await batchReviewAlerts({
              alert_ids: items.map((i) => i.id),
              disposition: 'benign',
              note: '依變更單處置',
              batch_id: batchId,
              self_triggered_ack: items.filter((i) => i.self).length,
            }, { skipErrorToast: true })
            const patches = {}
            for (const item of body.items || []) patches[item.id] = itemPatch(item, 'benign')
            return patches
          },
        })
        outcome.value = res.outcome
      }
      expose({ ...api, outcome })
      return () => h('div', [
        h('button', { 'data-test': 'submit', onClick: submit }),
        h('button', { 'data-test': 'recheck', onClick: () => api.recheck() }),
        h('button', { 'data-test': 'recover', onClick: () => api.recover() }),
      ])
    },
  })

  const entries = (n, selfEvery = 2) => Array.from({ length: n }, (_, i) => ({ id: 1000 + i, label: `#${1000 + i}`, self: i % selfEvery === 0 }))
  const posts = () => requestMock.mock.calls.filter(([cfg]) => cfg.method === 'post')
  const gets = () => requestMock.mock.calls.filter(([cfg]) => cfg.method === 'get')
  const stateOf = (w) => w.vm.items.map((i) => i.state)

  beforeEach(() => {
    requestMock.mockReset()
    sessionStorage.clear()
    clock = Date.now()
  })

  async function submitWith(w) {
    await w.find('[data-test="submit"]').trigger('click')
    await flushPromises()
  }

  it('106 筆只發出 1 個批次請求，本文帶 alert_ids、處置、理由、UUID 關聯碼與本人觸發筆數，逾時 45 秒', async () => {
    requestMock.mockImplementation(async (cfg) => ({
      batch_id: cfg.data.batch_id, limit: 500,
      summary: { reviewed: 106 },
      items: cfg.data.alert_ids.map((id) => ({ id, result: 'reviewed', self_triggered: false })),
    }))
    const w = mount(Harness, { props: { entries: entries(106) } })
    await submitWith(w)
    expect(posts()).toHaveLength(1)
    const [cfg] = posts()[0]
    expect(cfg.url).toBe('/command-alerts/batch-review')
    expect(cfg.timeout).toBe(45_000)
    expect(cfg.data.alert_ids).toHaveLength(106)
    expect(cfg.data.disposition).toBe('benign')
    expect(cfg.data.note).toBe('依變更單處置')
    expect(cfg.data.batch_id).toMatch(UUID_V4)
    expect(cfg.data.self_triggered_ack).toBe(53)
    expect(stateOf(w).every((s) => s === BATCH_STATE.SUCCESS)).toBe(true)
  })

  it('沒有回應：106 筆都標待確認；按重新查詢以 50、50、6 分段查回，依審閱者與處置分類判定', async () => {
    requestMock.mockImplementation(async (cfg) => {
      if (cfg.method === 'post') throw Object.assign(new Error('timeout'), { code: 'ECONNABORTED', request: {} })
      const ids = cfg.params.ids.split(',').map(Number)
      return {
        data: ids.map((id) => {
          if (id === 1000) return { id, reviewed_at: 'x', reviewed_by: ME, disposition: 'benign', note: '依變更單處置' }
          if (id === 1001) return { id, reviewed_at: 'x', reviewed_by: 99, disposition: 'escalated', note: '' }
          if (id === 1002) return { id, reviewed_at: 'x', reviewed_by: ME, disposition: 'escalated', note: '先前逐筆' }
          return { id, reviewed_at: null }
        }),
      }
    })
    const w = mount(Harness, { props: { entries: entries(106) } })
    await submitWith(w)
    expect(w.vm.outcome).toBe(BULK_OUTCOME.UNCONFIRMED)
    expect(stateOf(w).every((s) => s === BATCH_STATE.UNCONFIRMED)).toBe(true)
    expect(gets()).toHaveLength(0) // 不自動查、不自動重送
    clock = Date.parse(w.vm.batch.startedAt) + 35_000
    await w.find('[data-test="recheck"]').trigger('click')
    await flushPromises()
    expect(gets().map(([cfg]) => cfg.params.ids.split(',').length)).toEqual([50, 50, 6])
    expect(posts()).toHaveLength(1)
    const byId = Object.fromEntries(w.vm.items.map((i) => [i.id, i]))
    expect(byId[1000].state).toBe(BATCH_STATE.SUCCESS)
    expect(byId[1001]).toMatchObject({ state: BATCH_STATE.NOT_APPLIED, reason: NOT_APPLIED_REASON.BY_OTHER, existing: 'escalated' })
    expect(byId[1002]).toMatchObject({ state: BATCH_STATE.NOT_APPLIED, reason: NOT_APPLIED_REASON.YOU_DIFFERENT })
    expect(byId[1003]).toMatchObject({ state: BATCH_STATE.NOT_APPLIED, reason: NOT_APPLIED_REASON.NOT_DELIVERED })
  })

  it('查回時仍未審閱：送出後 10 秒維持待確認，35 秒後才算沒有生效', async () => {
    requestMock.mockImplementation(async (cfg) => {
      if (cfg.method === 'post') throw Object.assign(new Error('Network Error'), { request: {} })
      return { data: cfg.params.ids.split(',').map((id) => ({ id: Number(id), reviewed_at: null })) }
    })
    const w = mount(Harness, { props: { entries: entries(3) } })
    await submitWith(w)
    const sent = Date.parse(w.vm.batch.startedAt)
    clock = sent + 10_000
    await w.find('[data-test="recheck"]').trigger('click')
    await flushPromises()
    expect(stateOf(w)).toEqual([BATCH_STATE.UNCONFIRMED, BATCH_STATE.UNCONFIRMED, BATCH_STATE.UNCONFIRMED])
    expect(w.vm.items[0].stillProcessing).toBe(true)
    clock = sent + 35_000
    await w.find('[data-test="recheck"]').trigger('click')
    await flushPromises()
    expect(stateOf(w)).toEqual([BATCH_STATE.NOT_APPLIED, BATCH_STATE.NOT_APPLIED, BATCH_STATE.NOT_APPLIED])
  })

  it('500 帶 INTERNAL_ALERT_REVIEW：整批沒有生效，回到填寫畫面', async () => {
    requestMock.mockRejectedValue({ response: { status: 500, data: { code: 'INTERNAL_ALERT_REVIEW' } } })
    const w = mount(Harness, { props: { entries: entries(4) } })
    await submitWith(w)
    expect(w.vm.outcome).toBe(BULK_OUTCOME.FAILED)
    expect(w.vm.phase).toBe('idle')
    expect(sessionStorage.getItem(KEY)).toBeNull()
  })

  it('502、沒有碼的 500、其他內部錯誤碼：歸待確認，不說沒有生效', async () => {
    for (const response of [
      { status: 502, data: {} },
      { status: 500, data: {} },
      { status: 500, data: { code: 'INTERNAL_SERVER_ERROR' } },
      // 後端在提交階段結果無法確定時回的碼
      { status: 500, data: { code: 'INTERNAL_COMMAND_ALERT_QUERY' } },
    ]) {
      requestMock.mockReset()
      requestMock.mockRejectedValue({ response })
      sessionStorage.clear()
      const w = mount(Harness, { props: { entries: entries(4) } })
      await submitWith(w)
      expect(w.vm.outcome).toBe(BULK_OUTCOME.UNCONFIRMED)
      expect(stateOf(w).every((s) => s === BATCH_STATE.UNCONFIRMED)).toBe(true)
      w.unmount()
    }
  })

  it('重新掛載：整批標待確認並查回，不自動重送；以紀錄的送出時刻判斷', async () => {
    const write = (startedAt) => sessionStorage.setItem(KEY, JSON.stringify({
      v: 1, batchId: generateBatchId(), kind: 'alert-bulk', mode: 'bulk', userId: ME, startedAt,
      params: { disposition: 'benign', note: '依變更單處置' },
      items: [{ id: 1, label: '#1', state: 'inflight' }, { id: 2, label: '#2', state: 'inflight' }],
    }))
    requestMock.mockImplementation(async (cfg) => ({ data: cfg.params.ids.split(',').map((id) => ({ id: Number(id), reviewed_at: null })) }))
    clock = Date.now()
    write(new Date(clock - 5_000).toISOString())
    let w = mount(Harness)
    await w.find('[data-test="recover"]').trigger('click')
    await flushPromises()
    expect(posts()).toHaveLength(0)
    expect(gets()).toHaveLength(1)
    expect(stateOf(w)).toEqual([BATCH_STATE.UNCONFIRMED, BATCH_STATE.UNCONFIRMED])
    w.unmount()

    write(new Date(clock - 60_000).toISOString())
    w = mount(Harness)
    await w.find('[data-test="recover"]').trigger('click')
    await flushPromises()
    expect(posts()).toHaveLength(0)
    expect(stateOf(w)).toEqual([BATCH_STATE.NOT_APPLIED, BATCH_STATE.NOT_APPLIED])
  })

  it('審核中心與多日簽核共用的逐筆批次上限維持 50', () => {
    expect(BATCH_LIMIT).toBe(50)
  })
})

describe('批次結果與查回的判讀（驗收補測）', () => {
  it('重送同一批：本人先前以相同處置處置過的項目算沒有生效，不算這一次成功', () => {
    const patch = itemPatch({ id: 1, result: 'already_reviewed', reviewed_by_you: true, existing_disposition: 'benign' }, 'benign')
    expect(patch.state).toBe(BATCH_STATE.NOT_APPLIED)
    expect(patch.state).not.toBe(BATCH_STATE.SUCCESS)
    expect(patch.reason).toBe(NOT_APPLIED_REASON.BY_YOU)
    expect(patch.existing).toBe('benign')
  })

  it('查回時審閱者與處置都相同但理由不同：不是這一次的處置，算沒有生效', async () => {
    const entry = {
      userId: 7,
      startedAt: new Date(Date.now() - 1000).toISOString(),
      params: { disposition: 'benign', note: '依變更單 CHG-1 核對' },
      items: [
        { id: 11, state: BATCH_STATE.UNCONFIRMED },
        { id: 12, state: BATCH_STATE.UNCONFIRMED },
      ],
    }
    const search = vi.fn().mockResolvedValue({
      data: [
        { id: 11, reviewed_at: '2026-11-23T00:00:00Z', reviewed_by: 7, disposition: 'benign', note: '依變更單 CHG-1 核對' },
        { id: 12, reviewed_at: '2026-11-22T00:00:00Z', reviewed_by: 7, disposition: 'benign', note: '先前逐筆處置時寫的說明' },
      ],
    })
    const updates = await reconcileAlertBulk(entry, { search })
    expect(updates[11]).toMatchObject({ state: BATCH_STATE.SUCCESS, rechecked: true })
    expect(updates[12].state).toBe(BATCH_STATE.NOT_APPLIED)
    expect(updates[12].reason).toBe(NOT_APPLIED_REASON.BY_YOU)
  })
})
