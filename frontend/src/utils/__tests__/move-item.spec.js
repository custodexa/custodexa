import { describe, it, expect } from 'vitest'
import { moveItem } from '../move-item'

describe('moveItem', () => {
  it('moves an element forward', () => {
    expect(moveItem(['a', 'b', 'c'], 0, 2)).toEqual(['b', 'c', 'a'])
  })

  it('moves an element backward', () => {
    expect(moveItem(['a', 'b', 'c'], 2, 0)).toEqual(['c', 'a', 'b'])
  })

  it('returns a new array without mutating the original', () => {
    const original = ['a', 'b', 'c']
    const result = moveItem(original, 0, 1)
    expect(result).not.toBe(original)
    expect(original).toEqual(['a', 'b', 'c'])
  })

  it('returns the same array when from equals to', () => {
    const original = ['a', 'b']
    expect(moveItem(original, 1, 1)).toBe(original)
  })

  it('returns the same array on out-of-range indices', () => {
    const original = ['a', 'b']
    expect(moveItem(original, -1, 1)).toBe(original)
    expect(moveItem(original, 0, 5)).toBe(original)
  })
})
