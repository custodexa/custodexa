import { describe, it, expect } from 'vitest'
import { closeOthers, closeLeft, closeRight, closeAll } from '../tab-close'

const mk = (keys) => keys.map((k) => ({ key: k }))

describe('tab-close', () => {
  it('closeOthers 僅保留目標並啟用', () => {
    const { tabs, activeKey } = closeOthers(mk(['a', 'b', 'c']), 'b')
    expect(tabs.map((t) => t.key)).toEqual(['b'])
    expect(activeKey).toBe('b')
  })

  it('closeLeft 移除左側、保留 active 若仍存在', () => {
    const { tabs, activeKey } = closeLeft(mk(['a', 'b', 'c']), 'b', 'c')
    expect(tabs.map((t) => t.key)).toEqual(['b', 'c'])
    expect(activeKey).toBe('c')
  })

  it('closeLeft 對首位無作用', () => {
    const input = mk(['a', 'b'])
    const { tabs, activeKey } = closeLeft(input, 'a', 'b')
    expect(tabs).toBe(input)
    expect(activeKey).toBe('b')
  })

  it('closeRight 移除右側、active 被關閉時退至尾端', () => {
    const { tabs, activeKey } = closeRight(mk(['a', 'b', 'c']), 'a', 'c')
    expect(tabs.map((t) => t.key)).toEqual(['a'])
    expect(activeKey).toBe('a')
  })

  it('closeAll 清空', () => {
    expect(closeAll()).toEqual({ tabs: [], activeKey: '' })
  })

  it('不變更輸入陣列', () => {
    const input = mk(['a', 'b', 'c'])
    closeOthers(input, 'b')
    closeLeft(input, 'b', 'c')
    closeRight(input, 'b', 'c')
    expect(input.map((t) => t.key)).toEqual(['a', 'b', 'c'])
  })
})
