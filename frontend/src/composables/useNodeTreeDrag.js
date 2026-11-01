// 節點樹拖拉搬移的判定與計算（純函式，不碰 DOM，供元件與單元測試共用）。
import { hasRowFlags, scopedActionStates, filterMoveCandidates } from '@/composables/useNodeTreeScope'

/** 停留多久自動展開收合的目標（毫秒） */
export const AUTO_EXPAND_MS = 700
/** 游標停在列上多久顯示停留說明卡（毫秒） */
export const ROW_TIP_DELAY_MS = 400
/** 距樹欄位上下緣多近開始邊緣捲動（像素） */
export const EDGE_SCROLL_ZONE_PX = 32
/** 邊緣捲動每幀上限（像素） */
export const EDGE_SCROLL_MAX_PX = 12
/** 成功、取消、被拒後原位或新位置標亮的時間（毫秒） */
export const FLASH_MS = 2000
/** 節點樹深度上限（與後端同口徑，根層為第 1 層） */
export const MAX_NODE_DEPTH = 10
/** 說明框寬度與高度估計（像素），用於夾在樹欄位範圍內 */
export const TIP_WIDTH_PX = 204
export const TIP_HEIGHT_PX = 84
/** 確認框寬度與高度估計（像素） */
export const CONFIRM_WIDTH_PX = 360
export const CONFIRM_HEIGHT_PX = 340

/**
 * 可不可以拖。ctx = { dragGateOn, canManageNodes, busy }。
 * 與「⋯ → 搬移」同一判斷來源：帶旗標的節點看 move 項，否則看 canManageNodes。
 */
export function canDragNode(data, ctx) {
  if (!ctx?.dragGateOn) return { ok: false, reason: '' }
  if (ctx.busy) return { ok: false, reason: '' }
  if (hasRowFlags(data)) {
    const state = scopedActionStates(data).move
    if (state.visible && !state.disabled) return { ok: true, reason: '' }
    return { ok: false, reason: state.visible ? state.reason : '' }
  }
  return { ok: !!ctx.canManageNodes, reason: '' }
}

/** 由被拖節點往上找第一個範圍根祖先的名稱，找不到回 '' */
export function findScopeRootName(node) {
  let cur = node?.parent
  while (cur && cur.level > 0) {
    if (cur.data?.scope_root === true) return cur.data.name || ''
    cur = cur.parent
  }
  return ''
}

/**
 * 可不可以放（只回答 inner）。dragging、drop 是 el-tree 的 Node。
 * 回傳 { code, ok, scopeName? }；code ∈ source｜self｜already｜noPermission｜depth｜sameName｜ok
 */
export function dropVerdict(dragging, drop, ctx) {
  if (!dragging || !drop) return { code: 'source', ok: false }
  if (drop === dragging) return { code: 'source', ok: false }
  if (dragging.contains?.(drop)) return { code: 'self', ok: false }
  const parentId = dragging.data?.parent_id ?? null
  if (drop.data?.id === parentId) return { code: 'already', ok: false }
  const dropData = drop.data || {}
  const permitted = hasRowFlags(dropData) ? dropData.can_create_child === true : !!ctx?.canManageNodes
  if (!permitted) return { code: 'noPermission', ok: false, scopeName: findScopeRootName(dragging) }
  if (drop.level >= MAX_NODE_DEPTH) return { code: 'depth', ok: false }
  if (drop.loaded === true) {
    const clash = (drop.childNodes || []).some(
      (c) => c.data?.name === dragging.data?.name && c.data?.id !== dragging.data?.id
    )
    if (clash) return { code: 'sameName', ok: false }
  }
  return { code: 'ok', ok: true }
}

/** 拖曳開始時記下原位置，供放下後還原 */
export function captureOrigin(node) {
  const parent = node.parent
  const next = node.nextSibling
  return {
    id: node.data.id,
    parentKey: !parent || parent.level === 0 ? null : parent.data.id,
    nextKey: next?.data?.id ?? null,
    expanded: !!node.expanded,
  }
}

/** 選取是否跟到新位置：被搬的是選取節點，或是選取節點的上層 */
export function selectionFollows(movedId, selectedKey, selectedAncestorIds = []) {
  if (selectedKey === null || selectedKey === undefined || selectedKey === 'ungrouped') return false
  return selectedKey === movedId || selectedAncestorIds.includes(movedId)
}

/** 逐碼位比較（與資料庫碼位排序一致） */
export function compareByCodePoint(a, b) {
  const x = Array.from(String(a))
  const y = Array.from(String(b))
  const n = Math.min(x.length, y.length)
  for (let i = 0; i < n; i += 1) {
    const d = x[i].codePointAt(0) - y[i].codePointAt(0)
    if (d !== 0) return d
  }
  return x.length - y.length
}

/**
 * 搬移請求失敗的分類：有後端回應且不是閘道逾時＝寫入被拒（交易已回滾）；
 * 沒有回應或 502／504＝結果未知（後端可能已提交）。
 */
export function classifyMoveError(error) {
  const status = error?.response?.status
  if (!error?.response) return 'unknown'
  if (status === 502 || status === 504) return 'unknown'
  return 'rejected'
}

/** 被拒原因：依錯誤碼回原因鍵與下一步鍵；其餘回 null（改顯示 resolveApiError 同一句） */
export function rejectKeysFor(code) {
  switch (code) {
    case 'CONFLICT_ASSET_NODE_NAME':
      return { reason: 'nodeTree.moveConfirm.rejectSameName', next: 'nodeTree.moveConfirm.rejectSameNameNext' }
    case 'RULE_NODE_DEPTH_EXCEEDED':
      return { reason: 'nodeTree.moveConfirm.rejectDepth', next: 'nodeTree.moveConfirm.rejectDepthNext' }
    case 'NOTFOUND_ASSET_NODE':
      return { reason: 'nodeTree.moveConfirm.rejectGone', next: 'nodeTree.moveConfirm.rejectGoneNext' }
    default:
      return null
  }
}

const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v))

/**
 * 說明框座標（視窗座標，以 fixed 定位）：預設放在該列右側，左緣從樹欄右緣起，
 * 垂直對齊該列頂端（夾在視窗內），蓋在右側列表上方而不遮樹列；
 * 視窗右側放不下時才退回列下方（水平夾在樹欄位內）。
 * row／container 為 { top, bottom, left, right } 的視窗座標矩形；viewport 為 { width, height }。
 */
export function placeTip({ row, container, cursorX, viewport, width = TIP_WIDTH_PX, height = TIP_HEIGHT_PX }) {
  const gap = 4
  const vw = viewport?.width ?? (typeof window !== 'undefined' ? window.innerWidth : 0)
  const vh = viewport?.height ?? (typeof window !== 'undefined' ? window.innerHeight : 0)
  const right = container.right + gap
  if (!vw || right + width <= vw - 8) {
    const maxTop = vh ? Math.max(8, vh - height - 8) : row.top
    return { left: right, top: clamp(row.top, 8, maxTop), side: 'right' }
  }
  const cw = container.right - container.left
  const left = container.left + clamp((cursorX ?? container.left) - container.left - width / 2, 0, Math.max(0, cw - width))
  return { left, top: row.bottom + 2, side: 'below' }
}

/** 最近的可捲動祖先（含自身）：實際溢出者才算；找不到回 null */
export function findScrollParent(el) {
  for (let cur = el; cur && cur.nodeType === 1; cur = cur.parentElement) {
    const oy = getComputedStyle(cur).overflowY
    if ((oy === 'auto' || oy === 'scroll' || oy === 'overlay') && cur.scrollHeight > cur.clientHeight) return cur
  }
  return null
}

/** 邊緣捲動的觸發範圍：樹欄位、捲動容器與視窗三者可見區的交集（視窗座標） */
export function visibleScrollRect(treeRect, scrollerRect, viewportHeight) {
  return {
    top: Math.max(treeRect.top, scrollerRect ? scrollerRect.top : treeRect.top, 0),
    bottom: Math.min(treeRect.bottom, scrollerRect ? scrollerRect.bottom : treeRect.bottom, viewportHeight),
  }
}

/**
 * 確認框座標（視窗座標）：錨在目標列旁，預設放在列右側，右側放不下改放左側，
 * 垂直置中於該列並夾在視窗內；回傳 arrow 指示框相對目標列的方向。
 */
export function placeConfirm({ row, viewport, width = CONFIRM_WIDTH_PX, height = CONFIRM_HEIGHT_PX }) {
  const gap = 12
  let side = 'right'
  let left = row.right + gap
  if (left + width > viewport.width) {
    side = 'left'
    left = row.left - gap - width
  }
  left = clamp(left, 8, Math.max(8, viewport.width - width - 8))
  const rowMid = (row.top + row.bottom) / 2
  const top = clamp(rowMid - height / 2, 8, Math.max(8, viewport.height - height - 8))
  return { left, top, side, arrowTop: clamp(rowMid - top, 16, height - 16) }
}

/** 邊緣捲動速度（帶正負號；負＝往上）。越靠邊越快，超過區域回 0 */
export function edgeScrollDelta(clientY, rect) {
  const fromTop = clientY - rect.top
  const fromBottom = rect.bottom - clientY
  if (fromTop >= 0 && fromTop < EDGE_SCROLL_ZONE_PX) {
    return -Math.max(1, Math.min(EDGE_SCROLL_MAX_PX, Math.ceil(((EDGE_SCROLL_ZONE_PX - fromTop) / EDGE_SCROLL_ZONE_PX) * EDGE_SCROLL_MAX_PX)))
  }
  if (fromBottom >= 0 && fromBottom < EDGE_SCROLL_ZONE_PX) {
    return Math.max(1, Math.min(EDGE_SCROLL_MAX_PX, Math.ceil(((EDGE_SCROLL_ZONE_PX - fromBottom) / EDGE_SCROLL_ZONE_PX) * EDGE_SCROLL_MAX_PX)))
  }
  return 0
}

/** 該自動展開嗎：收合的非葉節點，且不是被拖節點本身或其子孫、也不是第 10 層 */
export function shouldAutoExpand(dragging, drop) {
  if (!dragging || !drop) return false
  if (drop.expanded || drop.isLeaf) return false
  if (drop === dragging || dragging.contains?.(drop)) return false
  if (drop.level >= MAX_NODE_DEPTH) return false
  return true
}

/**
 * 搬移對話框的候選樹：排除自身與整個子樹，候選依旗標收斂；
 * 根層與每層依原始節點名稱逐碼位排序（與節點樹同層順序一致）。
 */
export function buildMoveOptions(flat, excludeId) {
  const childrenOf = new Map()
  flat.forEach((n) => {
    if (n.parent_id != null) {
      if (!childrenOf.has(n.parent_id)) childrenOf.set(n.parent_id, [])
      childrenOf.get(n.parent_id).push(n.id)
    }
  })
  const excluded = new Set([excludeId])
  const queue = [excludeId]
  while (queue.length) {
    const cur = queue.shift()
    for (const child of childrenOf.get(cur) || []) {
      if (!excluded.has(child)) {
        excluded.add(child)
        queue.push(child)
      }
    }
  }
  const byId = new Map()
  filterMoveCandidates(flat).forEach((n) => {
    if (!excluded.has(n.id)) {
      byId.set(n.id, { id: n.id, name: n.path || n.name, rawName: n.name, parent_id: n.parent_id, children: [] })
    }
  })
  const roots = []
  byId.forEach((n) => {
    if (n.parent_id && byId.has(n.parent_id)) byId.get(n.parent_id).children.push(n)
    else roots.push(n)
  })
  const sortRec = (list) => {
    list.sort((a, b) => compareByCodePoint(a.rawName, b.rawName))
    list.forEach((n) => sortRec(n.children))
  }
  sortRec(roots)
  return roots
}
