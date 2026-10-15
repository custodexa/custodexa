import { describe, it, expect } from 'vitest'
import { highlightSegments, hostLineSegments } from '../workspace/highlight'

const hits = (segs) => segs.filter((s) => s.hit).map((s) => s.text)
const joined = (segs) => segs.map((s) => s.text).join('')

describe('highlightSegments', () => {
  it('沒有關鍵字時整段不標', () => {
    expect(highlightSegments('10.20.5.23', '')).toEqual([{ text: '10.20.5.23', hit: false }])
  })

  it('空字串回空陣列', () => {
    expect(highlightSegments('', 'a')).toEqual([])
    expect(highlightSegments(null, 'a')).toEqual([])
  })

  it('不分大小寫、保留原字樣、全部出現處都標', () => {
    const segs = highlightSegments('GW-a.gw.local', 'gw')
    expect(hits(segs)).toEqual(['GW', 'gw'])
    expect(joined(segs)).toBe('GW-a.gw.local')
  })

  it('關鍵字裡的點是字面字元，不當萬用字元', () => {
    expect(hits(highlightSegments('10x20x5', '10.20'))).toEqual([])
    expect(hits(highlightSegments('10.20.5.23', '10.20'))).toEqual(['10.20'])
  })

  it('沒有命中時整段不標', () => {
    expect(highlightSegments('10.1.0.1', '10.20')).toEqual([{ text: '10.1.0.1', hit: false }])
  })
})

describe('hostLineSegments', () => {
  it('只在位址段內標命中，標籤文字不參與', () => {
    const segs = hostLineSegments('Host 10.20.5.23:22', '10.20.5.23:22', 'host')
    expect(hits(segs)).toEqual([])
    const segs2 = hostLineSegments('主機位址 10.20.5.23:22', '10.20.5.23:22', '10.20.5')
    expect(hits(segs2)).toEqual(['10.20.5'])
    expect(joined(segs2)).toBe('主機位址 10.20.5.23:22')
    expect(segs2[0]).toEqual({ text: '主機位址 ', hit: false })
  })

  it('位址找不到時整行原樣、不標', () => {
    expect(hostLineSegments('Host x', '10.0.0.1', '10')).toEqual([{ text: 'Host x', hit: false }])
  })
})
