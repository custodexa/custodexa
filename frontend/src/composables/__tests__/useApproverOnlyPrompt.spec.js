import { describe, it, expect } from 'vitest'
import { ref } from 'vue'
import { useApproverOnlyPrompt, withGeneralUser } from '../useApproverOnlyPrompt'

const coded = (code) => ({ response: { status: 400, data: { error: 'x', code } } })
const legacy = (code) => ({ response: { status: 400, data: { error: { code } } } })

describe('useApproverOnlyPrompt', () => {
  it('只接這個碼（含舊式巢狀 error 物件）；其他錯誤交還呼叫端', () => {
    const p = useApproverOnlyPrompt()
    expect(p.capture(coded('AUTH_PROTECTED_ROLE_ASSIGNMENT'))).toBe(false)
    expect(p.visible.value).toBe(false)
    expect(p.capture(legacy('VALIDATION_ROLE_SET_APPROVER_ONLY'), 'create')).toBe(true)
    expect(p.copy.value.title).toBe('users.approverOnlyPrompt.createTitle')
    p.dismiss()
    expect(p.visible.value).toBe(false)
  })

  it('草稿的一般使用者限定在節點時用限定節點版，修正改為全系統並帶出 { user: null }', () => {
    const roles = ref(['user', 'approver'])
    const ranges = ref({ user: 'nodes' })
    const p = useApproverOnlyPrompt({
      roles,
      sources: [roles, ranges],
      isNodeScoped: (n) => ranges.value[n] === 'nodes',
      setGlobal: (n) => (ranges.value = { ...ranges.value, [n]: 'all' }),
    })
    expect(p.captureDraft(coded('VALIDATION_ROLE_SET_APPROVER_ONLY'))).toBe(true)
    expect(p.variant.value).toBe('widen')
    expect(p.toGlobalUser()).toEqual({ user: null })
    expect(roles.value).toEqual(['user', 'approver'])
    expect(ranges.value.user).toBe('all')
    // 草稿變動同步收起
    expect(p.visible.value).toBe(false)
  })

  it('草稿沒有一般使用者：加上全系統的一般使用者，不額外帶範圍；不改動傳入陣列', () => {
    const roles = ref(['approver'])
    const p = useApproverOnlyPrompt({ roles, sources: [roles], isNodeScoped: () => false, setGlobal: () => {} })
    expect(p.captureDraft(coded('VALIDATION_ROLE_SET_APPROVER_ONLY'))).toBe(true)
    expect(p.variant.value).toBe('add')
    const before = roles.value
    expect(p.toGlobalUser()).toEqual({})
    expect(roles.value).toEqual(['approver', 'user'])
    expect(before).toEqual(['approver'])
    expect(withGeneralUser(['user'])).toEqual(['user'])
  })
})
