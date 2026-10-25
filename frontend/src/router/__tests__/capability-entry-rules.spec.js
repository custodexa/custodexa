import { describe, it, expect, vi, beforeEach } from 'vitest'
import router, { createAuthGuard } from '../index'
import { ENTRY_RULES, canEnter, entryMeta, entryRuleFor, hasEntryRule } from '../entryRules'
import { resetSessionForTests, setAccessToken } from '@/utils/session'
import { meBody, permissionsFor } from '@/composables/__tests__/capabilityFixtures'

// 入口規則（permissionsAll／signedIn）的精確語義。
// 只驗：有／無所需能力的放行與拒絕、未知入口／鍵拒絕、detail／query 與列表同規則、
// 審核／agent 兩個衍生點、純 approver 的原登入即可入口仍可進入、
// 已登入者可進兩個自助頁且未登入者仍去登入。

const getCurrentUserMock = vi.fn()
vi.mock('@/api/auth', () => ({
  getCurrentUser: (...args) => getCurrentUserMock(...args),
  logout: vi.fn(),
}))

const guard = createAuthGuard()
const holds = (...perms) => (needed) => needed.every((p) => perms.includes(p))

describe('入口規則表', () => {
  it('共 35 個入口，不保留 roles 形狀，每條不是 signedIn 就是非空的 permissionsAll', () => {
    const entries = Object.entries(ENTRY_RULES)
    expect(entries).toHaveLength(35)
    for (const [path, rule] of entries) {
      expect(rule.roles, path).toBeUndefined()
      const signedIn = rule.signedIn === true
      const perms = rule.permissionsAll ?? rule.permissionsAny
      expect(rule.permissionsAll !== undefined && rule.permissionsAny !== undefined, path).toBe(false)
      expect(signedIn !== Array.isArray(perms), path).toBe(true)
      if (!signedIn) {
        expect(perms.length, path).toBeGreaterThan(0)
        // 完整鍵：resource:action 或 ui:name，不含萬用字元
        for (const p of perms) expect(p, path).toMatch(/^[a-z_]+:[a-z_-]+$/)
      }
    }
  })

  it('登入即可的入口恰為六個，含兩個自助頁', () => {
    const signedIn = Object.entries(ENTRY_RULES).filter(([, r]) => r.signedIn).map(([p]) => p).sort()
    expect(signedIn).toEqual(['/assets', '/dashboard', '/my-connections', '/my-requests', '/profile', '/workspace'])
  })

  it('detail 與 query 別名沿用所屬列表入口的規則', () => {
    expect(entryRuleFor('/users?kind=agent')).toBe(ENTRY_RULES['/users'])
    for (const [detail, list] of [
      ['/sessions/12', '/sessions'],
      ['/sessions/12/monitor', '/sessions'],
      ['/audit/agent-tasks/req-1', '/audit/agent-tasks'],
      ['/identity-sources/ldap/3', '/identity-sources'],
      ['/identity-sources/new/oidc', '/identity-sources'],
    ]) {
      const resolved = router.resolve(detail)
      expect(resolved.meta.permissionsAll, detail).toEqual(entryMeta(list).permissionsAll)
    }
  })

  it('未登記的入口一律拒絕：規則不存在、形狀不明、清單為空或含非字串都不放行', () => {
    expect(entryRuleFor('/no-such-page')).toBeUndefined()
    expect(() => entryMeta('/no-such-page')).toThrow()
    const all = holds('user:manage', 'asset:view')
    expect(canEnter(undefined, all)).toBe(false)
    expect(canEnter({}, all)).toBe(false)
    expect(canEnter({ permissionsAll: [] }, all)).toBe(false)
    expect(canEnter({ permissionsAll: [1] }, all)).toBe(false)
    expect(canEnter({ permissionsAll: [''] }, all)).toBe(false)
    expect(canEnter({ roles: ['admin'] }, all)).toBe(false)
    expect(canEnter({ signedIn: true, permissionsAll: ['asset:view'] }, all)).toBe(false)
    expect(canEnter({ permissionsAll: ['not:in:catalog'] }, holds())).toBe(false)
    expect(hasEntryRule({})).toBe(false)
    expect(hasEntryRule({ signedIn: true })).toBe(true)
    expect(hasEntryRule({ permissionsAll: ['x:y'] })).toBe(true)
  })

  it('有所需能力才放行；多鍵規則要全部持有', () => {
    const rule = { permissionsAll: ['audit:view', 'compliance:view'] }
    expect(canEnter(rule, holds('audit:view'))).toBe(false)
    expect(canEnter(rule, holds('audit:view', 'compliance:view'))).toBe(true)
    expect(canEnter({ signedIn: true }, holds())).toBe(true)
  })

  it('每個受限入口只被其所需能力打開：以管理員全集移除該入口的鍵就被拒', () => {
    const admin = permissionsFor(['admin'])
    for (const [path, rule] of Object.entries(ENTRY_RULES)) {
      if (rule.signedIn || rule.permissionsAny) continue // 任一形狀見 alerts-entry.spec.js
      // 管理員全集不含審核呈現點與 agent 入口（它們不是角色能力）
      const has = (perms) => perms.every((p) => admin.includes(p))
      const expected = rule.permissionsAll.every((p) => admin.includes(p))
      expect(canEnter(rule, has), path).toBe(expected)
      const without = (perms) => perms.every((p) => admin.includes(p) && !rule.permissionsAll.includes(p))
      expect(canEnter(rule, without), `${path} 少了所需鍵`).toBe(false)
    }
  })
})

describe('守衛與兩個衍生點', () => {
  let next
  beforeEach(() => {
    localStorage.clear()
    resetSessionForTests()
    getCurrentUserMock.mockReset()
    next = vi.fn()
  })

  const enter = async (path) => {
    const resolved = router.resolve(path)
    await guard({ path, meta: resolved.meta, query: {} }, { path: '/', meta: {} }, next)
  }

  it('審核點只來自既有審核資格；agent 入口只來自兩旗標，管理者不兜底', async () => {
    setAccessToken('t')
    getCurrentUserMock.mockResolvedValue(meBody(['admin'], { approver: false, owns: false, create: false }))
    await enter('/approvals')
    expect(next).toHaveBeenLastCalledWith('/dashboard')
    await enter('/my-agents')
    expect(next).toHaveBeenLastCalledWith('/dashboard')

    resetSessionForTests()
    setAccessToken('t')
    getCurrentUserMock.mockResolvedValue(meBody(['user'], { approver: true, create: true }))
    await enter('/approvals')
    expect(next).toHaveBeenLastCalledWith()
    await enter('/my-agents')
    expect(next).toHaveBeenLastCalledWith()
  })

  it('純審核者（無可指派能力）仍可進原本登入即可的入口與審核中心', async () => {
    setAccessToken('t')
    getCurrentUserMock.mockResolvedValue(meBody(['approver']))
    for (const path of ['/dashboard', '/workspace', '/profile', '/assets', '/my-connections', '/my-requests', '/approvals']) {
      await enter(path)
      expect(next, path).toHaveBeenLastCalledWith()
    }
    await enter('/sessions')
    expect(next).toHaveBeenLastCalledWith('/dashboard')
  })

  it('已登入者（含管理者與稽核人員）可進兩個自助頁；未登入者仍去登入', async () => {
    for (const roles of [['admin'], ['auditor'], ['user']]) {
      resetSessionForTests()
      setAccessToken('t')
      getCurrentUserMock.mockResolvedValue(meBody(roles))
      for (const path of ['/my-connections', '/my-requests']) {
        await enter(path)
        expect(next, `${roles} ${path}`).toHaveBeenLastCalledWith()
      }
    }
    resetSessionForTests()
    for (const path of ['/my-connections', '/my-requests']) {
      await enter(path)
      expect(next, path).toHaveBeenLastCalledWith('/login')
    }
  })
})
