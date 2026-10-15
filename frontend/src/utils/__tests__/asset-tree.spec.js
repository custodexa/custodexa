import { describe, it, expect } from 'vitest'
import { buildAssetTree, flattenTree, flatRows, rootKeys, allKeys, UNGROUPED_KEY } from '../asset-tree'

const a = (id, name, paths, extra = {}) => ({ id, name, node_paths: paths, ...extra })

describe('buildAssetTree', () => {
  it('依「 / 」拆段建樹，台數緊跟子樹資產數', () => {
    const { nodes, flat } = buildAssetTree([
      a(1, 'm1', ['prod / mysql']),
      a(2, 'm2', ['prod / mysql']),
      a(3, 'm3', ['prod / mysql']),
      a(4, 'r1', ['prod / redis']),
    ], { ungroupedLabel: '未分組' })
    expect(flat).toBe(false)
    expect(nodes).toHaveLength(1)
    const prod = nodes[0]
    expect([prod.name, prod.count]).toEqual(['prod', 4])
    expect(prod.children.map((c) => [c.name, c.count])).toEqual([['mysql', 3], ['redis', 1]])
  })

  it('多歸屬資產在每個節點各出現一次；同一子樹只算一台', () => {
    const { nodes } = buildAssetTree([
      a(1, 'zabbix', ['prod / elk', 'sit / elk']),
      a(2, 'both', ['prod / elk', 'prod / mysql']),
    ])
    const prod = nodes.find((n) => n.name === 'prod')
    const sit = nodes.find((n) => n.name === 'sit')
    expect(prod.children.find((c) => c.name === 'elk').assets.map((x) => x.id)).toEqual([2, 1])
    expect(sit.children[0].assets.map((x) => x.id)).toEqual([1])
    expect(prod.count).toBe(2)
  })

  it('未分組排最後；節點與資產按名稱排序（數字自然序）', () => {
    const { nodes } = buildAssetTree([
      a(1, 'tmp', []),
      a(2, 'web-10', ['uat']),
      a(3, 'web-2', ['uat']),
      a(4, 'x', ['prod']),
    ], { ungroupedLabel: '未分組' })
    expect(nodes.map((n) => n.name)).toEqual(['prod', 'uat', '未分組'])
    expect(nodes[1].assets.map((x) => x.name)).toEqual(['web-2', 'web-10'])
    expect(nodes[2].key).toBe(UNGROUPED_KEY)
  })

  it('全部未分組時 flat 為真', () => {
    const { nodes, flat } = buildAssetTree([a(1, 'x', []), a(2, 'y')], { ungroupedLabel: '未分組' })
    expect(flat).toBe(true)
    expect(flatRows(nodes).map((r) => r.asset.id)).toEqual([1, 2])
  })

  it('match 只收錄命中的「資產 × 路徑」，無命中節點不出現', () => {
    const { nodes } = buildAssetTree([
      a(1, 'es-1', ['prod / elk']),
      a(2, 'db-1', ['prod / mysql']),
    ], { match: (asset, path) => path.toLowerCase().includes('elk') })
    expect(nodes[0].children.map((c) => c.name)).toEqual(['elk'])
    expect(nodes[0].count).toBe(1)
  })
})

describe('flattenTree', () => {
  it('收合的節點不列子層；展開才列', () => {
    const { nodes } = buildAssetTree([a(1, 'm1', ['prod / mysql'])])
    const collapsed = flattenTree(nodes, () => false)
    expect(collapsed.map((r) => r.type)).toEqual(['node'])
    const open = flattenTree(nodes, () => true)
    expect(open.map((r) => [r.type, r.depth])).toEqual([['node', 0], ['node', 1], ['asset', 2]])
    expect(rootKeys(nodes)).toEqual(['prod'])
    expect(allKeys(nodes)).toEqual(['prod', 'prod / mysql'])
  })
})
