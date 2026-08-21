import { describe, it, expect } from 'vitest'
import {
  timeToPercent,
  spanGeometry,
  buildTicks,
} from '../timelineGeometry'
import {
  parseWorkbenchQuery,
  buildWorkbenchQuery,
  sameQuery,
  shortcutRange,
  toRfc3339Local,
} from '../timelineQuery'
import { TIMELINE_TYPES } from '../timelineSummary'

// 時間軸幾何與 query 序列化的純函式守衛。跨度條的四種情形（一般／進行中／
// 跨窗／0 秒）在 dev 資料湊不齊，以此處釘住行為。

const FROM = '2026-08-12T00:00:00+08:00'
const TO = '2026-08-12T12:00:00+08:00'
const at = (h, m = 0) =>
  `2026-08-12T${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:00+08:00`

describe('timeToPercent', () => {
  it('窗內線性映射、窗外裁切到 0/100', () => {
    expect(timeToPercent(at(6), FROM, TO)).toBeCloseTo(50, 5)
    expect(timeToPercent(at(0), FROM, TO)).toBe(0)
    expect(timeToPercent('2026-08-11T00:00:00+08:00', FROM, TO)).toBe(0)
    expect(timeToPercent('2026-08-13T00:00:00+08:00', FROM, TO)).toBe(100)
  })

  it('窗無效（to <= from）或時刻不可解析時回 null', () => {
    expect(timeToPercent(at(6), TO, FROM)).toBeNull()
    expect(timeToPercent('not-a-time', FROM, TO)).toBeNull()
  })
})

describe('spanGeometry 四種情形', () => {
  it('一般：起訖都在窗內', () => {
    const geo = spanGeometry({ start: at(3), end: at(6) }, FROM, TO)
    expect(geo.left).toBeCloseTo(25, 5)
    expect(geo.width).toBeCloseTo(25, 5)
    expect(geo.ongoing).toBe(false)
    expect(geo.clippedStart).toBe(false)
    expect(geo.clippedEnd).toBe(false)
    expect(geo.durationSeconds).toBe(3 * 3600)
  })

  it('進行中：end 為 null → ongoing，視覺終點取「現在」而非硬邊', () => {
    const now = new Date(at(9)).getTime()
    const geo = spanGeometry({ start: at(6), end: null }, FROM, TO, now)
    expect(geo.ongoing).toBe(true)
    expect(geo.clippedEnd).toBe(false)
    expect(geo.left).toBeCloseTo(50, 5)
    expect(geo.width).toBeCloseTo(25, 5)
  })

  it('跨窗：兩端都在窗外 → 兩端裁切旗標，時長仍是真實時長', () => {
    const geo = spanGeometry(
      { start: '2026-08-11T20:00:00+08:00', end: '2026-08-12T20:00:00+08:00' },
      FROM,
      TO
    )
    expect(geo.clippedStart).toBe(true)
    expect(geo.clippedEnd).toBe(true)
    expect(geo.left).toBe(0)
    expect(geo.width).toBe(100)
    expect(geo.durationSeconds).toBe(24 * 3600)
  })

  it('0 秒會話：寬度為 0（可見寬度由 CSS min-width 保底），仍算 visible', () => {
    const geo = spanGeometry({ start: at(6), end: at(6) }, FROM, TO)
    expect(geo.width).toBe(0)
    expect(geo.visible).toBe(true)
    expect(geo.durationSeconds).toBe(0)
  })

  it('完全落在窗外的會話標為不可見（呼叫端不畫）', () => {
    const geo = spanGeometry(
      { start: '2026-08-10T01:00:00+08:00', end: '2026-08-10T02:00:00+08:00' },
      FROM,
      TO
    )
    expect(geo.visible).toBe(false)
  })
})

describe('buildTicks', () => {
  it('刻度落在窗內且百分比單調遞增', () => {
    const ticks = buildTicks(FROM, TO, 8)
    expect(ticks.length).toBeGreaterThan(2)
    expect(ticks.length).toBeLessThanOrEqual(40)
    for (let i = 1; i < ticks.length; i += 1) {
      expect(ticks[i].percent).toBeGreaterThan(ticks[i - 1].percent)
    }
    expect(ticks[0].percent).toBeGreaterThanOrEqual(0)
    expect(ticks[ticks.length - 1].percent).toBeLessThanOrEqual(100)
  })

  it('窗無效時回空陣列（不得丟例外把整頁帶掉）', () => {
    expect(buildTicks(TO, FROM)).toEqual([])
    expect(buildTicks('', '')).toEqual([])
  })
})

describe('query 序列化', () => {
  it('types 三態：缺席＝全部、空字串＝全關、csv＝子集', () => {
    expect(parseWorkbenchQuery({}).types).toEqual(TIMELINE_TYPES)
    expect(parseWorkbenchQuery({ types: '' }).types).toEqual([])
    expect(parseWorkbenchQuery({ types: 'alert,command,不存在' }).types).toEqual([
      'alert',
      'command',
    ])
  })

  it('build → parse 往返一致（含全關與 focus）', () => {
    const state = {
      subject: 'asset',
      subjectId: 7,
      from: FROM,
      to: TO,
      types: ['alert'],
      focus: 'alert:12',
      view: 'table',
    }
    const parsed = parseWorkbenchQuery(buildWorkbenchQuery(state))
    expect(parsed).toEqual(state)

    const allOff = { ...state, types: [] }
    expect(parseWorkbenchQuery(buildWorkbenchQuery(allOff)).types).toEqual([])
  })

  it('全部類別開啟時省略 types 參數（＝全部，與後端語義一致）', () => {
    const q = buildWorkbenchQuery({
      subject: 'user',
      subjectId: 1,
      from: FROM,
      to: TO,
      types: [...TIMELINE_TYPES],
      view: 'timeline',
    })
    expect(q.types).toBeUndefined()
    expect(q.view).toBeUndefined()
  })

  it('sameQuery 區分「缺席」與「空字串」（全開 vs 全關不可視為相同）', () => {
    expect(sameQuery({ subject: 'user' }, { subject: 'user', types: '' })).toBe(false)
    expect(sameQuery({ subject: 'user', id: '3' }, { subject: 'user', id: 3 })).toBe(true)
  })

  it('壞掉的 id 與時間一律回落為未指定（不得把 NaN 送進查詢）', () => {
    const parsed = parseWorkbenchQuery({ id: 'abc', from: 'x', to: TO })
    expect(parsed.subjectId).toBeNull()
    expect(parsed.from).toBe('')
  })

  it('RFC3339 一律帶時區偏移（後端拒收只有日期的參數）', () => {
    const [from, to] = shortcutRange('today', new Date('2026-08-12T09:30:00Z'))
    expect(from).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$/)
    expect(to).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$/)
    expect(new Date(to) - new Date(from)).toBe(24 * 3600 * 1000)
  })

  it('±30 分鐘快捷以錨點為中心', () => {
    const anchor = new Date('2026-08-12T09:30:00Z')
    const [from, to] = shortcutRange('around30m', anchor)
    expect(new Date(from).toISOString()).toBe('2026-08-12T09:00:00.000Z')
    expect(new Date(to).toISOString()).toBe('2026-08-12T10:00:00.000Z')
    expect(toRfc3339Local(new Date('invalid'))).toBe('')
  })
})
