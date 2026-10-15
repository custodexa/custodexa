/**
 * 工作區側欄的分組樹（純函式）。
 *
 * 資產列帶的 `node_paths` 是伺服端以 `" / "` 串起的節點完整路徑；這裡依分隔
 * 拆段建樹，多歸屬資產在每個歸屬節點下各出現一次。節點名本身含 `" / "` 時
 * 會被多拆一層——只影響顯示層級，不影響資產歸屬與台數。
 */

export const PATH_SEPARATOR = ' / '
/** 未分組節點的鍵：不可能與真實路徑撞名 */
export const UNGROUPED_KEY = '\u0000ungrouped'

const byName = (a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' })

function makeNode(key, name, depth) {
  return { key, name, depth, count: 0, children: [], assets: [], childMap: new Map() }
}

function uniquePaths(asset) {
  const raw = Array.isArray(asset?.node_paths) ? asset.node_paths : []
  return [...new Set(raw.filter((p) => typeof p === 'string' && p.trim()))]
}

/** 節點子樹內的資產 id 集合（多歸屬資產在同一子樹只算一台） */
function finalize(node) {
  const ids = new Set(node.assets.map((a) => a.id))
  const children = [...node.childMap.values()].sort((x, y) => byName(x.name, y.name))
  for (const child of children) {
    for (const id of finalize(child)) ids.add(id)
  }
  node.children = children
  node.assets = [...node.assets].sort((x, y) => byName(String(x.name ?? ''), String(y.name ?? '')))
  node.count = ids.size
  delete node.childMap
  return ids
}

/**
 * @param {object[]} assets 資產列
 * @param {{ ungroupedLabel?: string, match?: (asset: object, pathText: string) => boolean }} options
 *   match 有給時只收錄回傳真的「資產 × 歸屬路徑」組合（搜尋用）
 * @returns {{ nodes: object[], flat: boolean }} flat＝全部未分組（不顯示樹頭）
 */
export function buildAssetTree(assets, { ungroupedLabel = '', match = null } = {}) {
  const roots = new Map()
  const ungrouped = makeNode(UNGROUPED_KEY, ungroupedLabel, 0)

  for (const asset of assets || []) {
    const paths = uniquePaths(asset)
    if (!paths.length) {
      if (!match || match(asset, ungroupedLabel)) ungrouped.assets.push(asset)
      continue
    }
    for (const path of paths) {
      if (match && !match(asset, path)) continue
      const segments = path.split(PATH_SEPARATOR).map((s) => s.trim()).filter(Boolean)
      if (!segments.length) continue
      let level = roots
      let node = null
      segments.forEach((name, depth) => {
        const key = segments.slice(0, depth + 1).join(PATH_SEPARATOR)
        if (!level.has(key)) level.set(key, makeNode(key, name, depth))
        node = level.get(key)
        level = node.childMap
      })
      node.assets.push(asset)
    }
  }

  const nodes = [...roots.values()].sort((x, y) => byName(x.name, y.name))
  for (const node of nodes) finalize(node)
  finalize(ungrouped)
  // 未分組永遠排最後
  if (ungrouped.assets.length) nodes.push(ungrouped)
  return { nodes, flat: nodes.length === 1 && nodes[0].key === UNGROUPED_KEY }
}

/**
 * 依展開狀態攤平成渲染用的列（節點列在前、其下子節點，再其下資產）
 * @param {object[]} nodes buildAssetTree 的 nodes
 * @param {(key: string) => boolean} isExpanded
 * @returns {object[]} `{ type: 'node', node, depth }` 或 `{ type: 'asset', asset, depth, nodeKey, rowKey }`
 */
export function flattenTree(nodes, isExpanded) {
  const rows = []
  const walk = (node) => {
    rows.push({ type: 'node', node, depth: node.depth, rowKey: `n:${node.key}` })
    if (!isExpanded(node.key)) return
    for (const child of node.children) walk(child)
    for (const asset of node.assets) {
      rows.push({ type: 'asset', asset, depth: node.depth + 1, nodeKey: node.key, rowKey: `a:${node.key}:${asset.id}` })
    }
  }
  for (const node of nodes) walk(node)
  return rows
}

/** 全部未分組時直接列資產（不顯示樹頭） */
export function flatRows(nodes) {
  const node = nodes[0]
  if (!node) return []
  return node.assets.map((asset) => ({ type: 'asset', asset, depth: 0, nodeKey: node.key, rowKey: `a:${node.key}:${asset.id}` }))
}

/** 第一層節點鍵（無保存紀錄時的預設展開集合） */
export function rootKeys(nodes) {
  return nodes.map((n) => n.key)
}

/** 所有節點鍵（搜尋時暫時全展開用） */
export function allKeys(nodes) {
  const keys = []
  const walk = (n) => {
    keys.push(n.key)
    n.children.forEach(walk)
  }
  nodes.forEach(walk)
  return keys
}
