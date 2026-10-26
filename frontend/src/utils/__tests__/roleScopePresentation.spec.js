import { describe, it, expect } from 'vitest'
import {
  SCOPE_CLASS,
  classifyRole,
  fromGroupBinding,
  fromUserBinding,
  summarizeScope,
  splitBuiltinCustom,
} from '../roleScopePresentation'

const NODES = [11, 12, 13, 14, 15].map((id) => ({ id, name: `n${id}`, path: `公司/區${id}` }))
const ctx = { nodes: NODES, canReadPaths: true }

describe('roleScopePresentation — 角色的範圍分類', () => {
  it('scopable 且範圍會生效', () => {
    expect(classifyRole({ scopable: true, node_range_no_effect: false, builtin_key: 'asset_admin' })).toBe(
      SCOPE_CLASS.EFFECTIVE
    )
  })

  it('範圍不會生效：原因 builtin_global_only 與 no_scoped_permission 各自分類', () => {
    const def = { scopable: true, node_range_no_effect: true, builtin_key: 'user' }
    expect(classifyRole(def, 'builtin_global_only')).toBe(SCOPE_CLASS.BUILTIN_GLOBAL_ONLY)
    expect(classifyRole(def, 'no_scoped_permission')).toBe(SCOPE_CLASS.NO_SCOPED_PERMISSION)
  })

  it('沒有原因時以 builtin_key 是否為空分辨', () => {
    expect(classifyRole({ scopable: true, node_range_no_effect: true, builtin_key: 'user' })).toBe(
      SCOPE_CLASS.BUILTIN_GLOBAL_ONLY
    )
    expect(classifyRole({ scopable: true, node_range_no_effect: true, builtin_key: null })).toBe(
      SCOPE_CLASS.NO_SCOPED_PERMISSION
    )
    expect(classifyRole({ scopable: true, node_range_no_effect: true })).toBe(SCOPE_CLASS.NO_SCOPED_PERMISSION)
  })

  it('scopable 為假判為不能限定；角色列表未載入判為未知', () => {
    expect(classifyRole({ scopable: false, node_range_no_effect: false })).toBe(SCOPE_CLASS.NOT_SCOPABLE)
    expect(classifyRole(undefined)).toBe(SCOPE_CLASS.UNKNOWN)
    expect(classifyRole({ name: 'x' })).toBe(SCOPE_CLASS.UNKNOWN)
  })
})

describe('roleScopePresentation — 管理範圍摘要', () => {
  it('scope global 為全系統', () => {
    const s = summarizeScope(fromGroupBinding({ role_id: 1, scope: 'global' }), ctx)
    expect(s.mode).toBe('all')
    expect(s.text).toBe('全系統')
  })

  it('五個節點列前三個路徑並以「等 2 個」收尾', () => {
    const s = summarizeScope(fromGroupBinding({ role_id: 1, scope: 'nodes', node_ids: [11, 12, 13, 14, 15] }), ctx)
    expect(s.items).toEqual(['公司/區11', '公司/區12', '公司/區13'])
    expect(s.text).toBe('公司/區11、公司/區12、公司/區13 等 2 個')
    expect(s.more).toBe(2)
  })

  it('不在節點清單的 ID 顯示節點已不存在，輸出不含該 ID', () => {
    const s = summarizeScope(fromGroupBinding({ role_id: 1, scope: 'nodes', node_ids: [11, 987654] }), ctx)
    expect(s.text).toContain('節點已不存在')
    expect(s.text).toContain('公司/區11')
    expect(JSON.stringify(s)).not.toContain('987654')
    expect(s.missing).toBe(1)
  })

  it('node_ids 為空或全數失效時輸出不含全系統字樣', () => {
    const empty = summarizeScope(fromGroupBinding({ role_id: 1, scope: 'nodes' }), ctx)
    const allMissing = summarizeScope(fromGroupBinding({ role_id: 1, scope: 'nodes', node_ids: [9001, 9002] }), ctx)
    expect(empty.text).not.toContain('全系統')
    expect(allMissing.text).not.toContain('全系統')
    expect(allMissing.text).toContain('節點已不存在')
  })

  it('不能讀路徑或節點清單讀取失敗時為「限定 N 個節點」', () => {
    const norm = fromGroupBinding({ role_id: 1, scope: 'nodes', node_ids: [11, 12] })
    expect(summarizeScope(norm, { nodes: NODES, canReadPaths: false }).text).toBe('限定 2 個節點')
    expect(summarizeScope(norm, { nodes: null, canReadPaths: true }).text).toBe('限定 2 個節點')
  })
})

describe('roleScopePresentation — 讀取形狀轉接', () => {
  it('fromGroupBinding：global 為全系統；nodes 而無 node_ids 鍵為節點範圍 0 個節點', () => {
    expect(fromGroupBinding({ role_id: 1, scope: 'global' })).toEqual({ roleId: 1, mode: 'all', nodeIds: [] })
    expect(fromGroupBinding({ role_id: 2, scope: 'nodes' })).toEqual({ roleId: 2, mode: 'nodes', nodeIds: [] })
  })

  it('fromUserBinding：無 node_ids 鍵為全系統；有鍵為節點範圍，空陣列也是', () => {
    expect(fromUserBinding({ role_id: 1 })).toEqual({ roleId: 1, mode: 'all', nodeIds: [] })
    expect(fromUserBinding({ role_id: 2, node_ids: [11] })).toEqual({ roleId: 2, mode: 'nodes', nodeIds: [11] })
    expect(fromUserBinding({ role_id: 3, node_ids: [] })).toEqual({ roleId: 3, mode: 'nodes', nodeIds: [] })
  })

  it('兩個 0 個節點的案例經摘要後都不含全系統字樣', () => {
    const a = summarizeScope(fromGroupBinding({ role_id: 2, scope: 'nodes' }), ctx)
    const b = summarizeScope(fromUserBinding({ role_id: 3, node_ids: [] }), ctx)
    expect(a.text).not.toContain('全系統')
    expect(b.text).not.toContain('全系統')
  })
})

describe('roleScopePresentation — 選單分組', () => {
  it('builtin_key 非空者在內建組並保留伺服器順序，其餘在自訂組', () => {
    const list = [
      { id: 1, builtin_key: 'user' },
      { id: 2, builtin_key: null },
      { id: 3, builtin_key: 'asset_admin' },
      { id: 4 },
      { id: 5, builtin_key: 'auditor' },
    ]
    const { builtin, custom } = splitBuiltinCustom(list)
    expect(builtin.map((x) => x.id)).toEqual([1, 3, 5])
    expect(custom.map((x) => x.id)).toEqual([2, 4])
  })
})
