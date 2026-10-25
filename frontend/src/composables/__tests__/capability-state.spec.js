import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  can,
  canAll,
  loadCapabilities,
  applyCurrentUser,
  resetCapabilities,
  useCapabilities,
} from '../useCapabilities'
import { clearSession, resetSessionForTests } from '@/utils/session'
import { meBody } from './capabilityFixtures'

// 目前使用者能力的共用狀態：載入、替換、會話結束與失敗。
// 只驗：首次缺欄不以角色放行、併發載入只發一次、成功替換不聯集舊能力、
// 登出／切帳號丟棄舊回應、刷新失敗保留同會話已載入快照且首次失敗可重試。

const getCurrentUserMock = vi.fn()
vi.mock('@/api/auth', () => ({
  getCurrentUser: (...args) => getCurrentUserMock(...args),
}))

const deferred = () => {
  let resolve
  let reject
  const promise = new Promise((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

describe('目前使用者能力狀態', () => {
  beforeEach(() => {
    localStorage.clear()
    resetSessionForTests()
    getCurrentUserMock.mockReset()
  })

  it('首次回應缺 permissions：不以角色放行，狀態為 error 並可重試', async () => {
    getCurrentUserMock.mockResolvedValue({ id: 1, roles: ['admin'], is_approver: true })
    expect(await loadCapabilities()).toBe(false)
    expect(useCapabilities().status.value).toBe('error')
    expect(can('user:manage')).toBe(false)
    expect(can('ui:approvals')).toBe(false)

    getCurrentUserMock.mockResolvedValue(meBody(['admin']))
    expect(await loadCapabilities()).toBe(true)
    expect(can('user:manage')).toBe(true)
  })

  it('尚未載入、型別錯誤、空字串與非字串鍵一律為否；canAll 不接受空清單', async () => {
    expect(can('asset:view')).toBe(false)
    getCurrentUserMock.mockResolvedValue({ id: 1, permissions: ['asset:view'] })
    await loadCapabilities()
    expect(can('asset:view')).toBe(true)
    expect(can('asset')).toBe(false) // 不做前綴比對
    expect(can('asset:*')).toBe(false) // 不做萬用比對
    expect(can('')).toBe(false)
    expect(can(null)).toBe(false)
    expect(canAll([])).toBe(false)
    expect(canAll(['asset:view', 'user:manage'])).toBe(false)
    expect(canAll(['asset:view'])).toBe(true)
  })

  it('併發載入只發一次請求，共用同一個結果', async () => {
    const d = deferred()
    getCurrentUserMock.mockReturnValue(d.promise)
    const first = loadCapabilities()
    const second = loadCapabilities()
    const third = loadCapabilities()
    d.resolve(meBody(['user']))
    expect(await Promise.all([first, second, third])).toEqual([true, true, true])
    expect(getCurrentUserMock).toHaveBeenCalledTimes(1)
    // 已就緒時不再發請求
    await loadCapabilities()
    expect(getCurrentUserMock).toHaveBeenCalledTimes(1)
  })

  it('成功更新整批替換，不與舊集合聯集', async () => {
    getCurrentUserMock.mockResolvedValue(meBody(['admin']))
    await loadCapabilities()
    expect(can('user:manage')).toBe(true)

    getCurrentUserMock.mockResolvedValue(meBody(['user']))
    await loadCapabilities({ force: true })
    expect(can('user:manage')).toBe(false)
    expect(can('ui:connect-bypass')).toBe(false)
    expect(can('asset:view')).toBe(true)

    // PATCH 回應走同一個替換入口
    expect(applyCurrentUser(meBody(['auditor']))).toBe(true)
    expect(can('audit:view')).toBe(true)
    expect(can('asset:view')).toBe(true)
    expect(can('session:terminate')).toBe(false)
  })

  it('登出：清空能力並丟棄仍在途的舊回應', async () => {
    const d = deferred()
    getCurrentUserMock.mockReturnValue(d.promise)
    const pending = loadCapabilities()
    clearSession() // 登出（或續期終敗、他分頁登出訊號）
    d.resolve(meBody(['admin']))
    expect(await pending).toBe(false)
    expect(can('user:manage')).toBe(false)
    expect(useCapabilities().status.value).toBe('idle')
  })

  it('切換帳號：前一個帳號的回應不覆蓋目前狀態', async () => {
    const oldAccount = deferred()
    getCurrentUserMock.mockReturnValueOnce(oldAccount.promise)
    const stale = loadCapabilities()
    resetCapabilities() // 換帳號登入前的清空

    getCurrentUserMock.mockResolvedValue(meBody(['user'], {}, { id: 2 }))
    await loadCapabilities()
    expect(can('asset:view')).toBe(true)

    oldAccount.resolve(meBody(['admin'], {}, { id: 1 }))
    await stale
    expect(can('user:manage')).toBe(false)
    expect(useCapabilities().loadedUserId.value).toBe(2)
  })

  it('已就緒後刷新失敗：保留同一會話已載入的快照', async () => {
    getCurrentUserMock.mockResolvedValue(meBody(['admin']))
    await loadCapabilities()
    getCurrentUserMock.mockRejectedValue(new Error('network'))
    expect(await loadCapabilities({ force: true })).toBe(true)
    expect(can('user:manage')).toBe(true)
    expect(useCapabilities().status.value).toBe('ready')
    // 回應不合格式的刷新同樣不動快照
    getCurrentUserMock.mockResolvedValue({ id: 1 })
    await loadCapabilities({ force: true })
    expect(can('user:manage')).toBe(true)
  })

  it('首次載入失敗：不開受限入口，可重試成功', async () => {
    getCurrentUserMock.mockRejectedValue(new Error('network'))
    expect(await loadCapabilities()).toBe(false)
    expect(useCapabilities().failed.value).toBe(true)
    expect(can('asset:view')).toBe(false)

    getCurrentUserMock.mockResolvedValue(meBody(['user']))
    expect(await useCapabilities().reload()).toBe(true)
    expect(useCapabilities().failed.value).toBe(false)
    expect(can('asset:view')).toBe(true)
  })

  it('product_version 隨回應更新，供側欄版本行共用', async () => {
    getCurrentUserMock.mockResolvedValue(meBody(['user'], {}, { product_version: '1.18.0' }))
    await loadCapabilities()
    expect(useCapabilities().productVersion.value).toBe('1.18.0')
  })

  describe('scope_summary 節點條目', () => {
    const entry = (perm, nodes) => ({ permission: perm, binding_scope: 'nodes', nodes })
    const nodeA = { id: 1, path: ['Alpha 機房', '核心 A'] }
    const nodeB = { id: 2, path: ['Beta 機房'] }

    it('新回應移除一個節點後，範圍摘要整批替換只剩其餘節點', async () => {
      getCurrentUserMock.mockResolvedValue(
        meBody(['user'], {}, { scope_summary: [entry('asset:view', [nodeA, nodeB])] }),
      )
      await loadCapabilities()
      expect(useCapabilities().scopeSummary.value[0].nodes).toEqual([nodeA, nodeB])
      expect(Array.isArray(useCapabilities().scopeSummary.value[0].nodes[0].path)).toBe(true)

      getCurrentUserMock.mockResolvedValue(
        meBody(['user'], {}, { scope_summary: [entry('asset:view', [nodeB])] }),
      )
      await loadCapabilities({ force: true })
      expect(useCapabilities().scopeSummary.value).toEqual([entry('asset:view', [nodeB])])
    })

    it('登出後 scope_summary 為空', async () => {
      getCurrentUserMock.mockResolvedValue(
        meBody(['user'], {}, { scope_summary: [entry('asset:view', [nodeA])] }),
      )
      await loadCapabilities()
      expect(useCapabilities().scopeSummary.value).toHaveLength(1)
      clearSession()
      expect(useCapabilities().scopeSummary.value).toEqual([])
    })

    it('前一帳號較晚到的回應不覆蓋目前的 scope_summary', async () => {
      const oldAccount = deferred()
      getCurrentUserMock.mockReturnValueOnce(oldAccount.promise)
      const stale = loadCapabilities()
      resetCapabilities()

      getCurrentUserMock.mockResolvedValue(
        meBody(['user'], {}, { id: 2, scope_summary: [entry('asset:view', [nodeB])] }),
      )
      await loadCapabilities()
      oldAccount.resolve(meBody(['user'], {}, { id: 1, scope_summary: [entry('asset:view', [nodeA])] }))
      await stale
      expect(useCapabilities().scopeSummary.value).toEqual([entry('asset:view', [nodeB])])
    })
  })
})
