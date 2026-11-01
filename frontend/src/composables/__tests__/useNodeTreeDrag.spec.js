import { describe, it, expect } from 'vitest'
import {
  canDragNode,
  dropVerdict,
  captureOrigin,
  selectionFollows,
  compareByCodePoint,
  classifyMoveError,
  placeTip,
  placeConfirm,
  edgeScrollDelta,
  visibleScrollRect,
  buildMoveOptions,
  AUTO_EXPAND_MS,
  EDGE_SCROLL_ZONE_PX,
  EDGE_SCROLL_MAX_PX,
  FLASH_MS,
} from '../useNodeTreeDrag'

// 最小的 el-tree Node 替身：parent 鏈、childNodes、contains
const mk = (data, { level = 1, parent = null, loaded = false, children = [] } = {}) => {
  const node = {
    data,
    level,
    parent,
    loaded,
    childNodes: children,
    expanded: false,
    contains(target) {
      return this.childNodes.some((c) => c === target || c.contains(target))
    },
  }
  children.forEach((c) => {
    c.parent = node
  })
  return node
}
const ctxOn = { dragGateOn: true, canManageNodes: true, busy: false }
const flagged = (extra) => ({ id: 1, name: 'n', can_rename: true, can_create_child: true, ...extra })

describe('canDragNode', () => {
  it('承載頁停用時不可拖、無原因', () => {
    expect(canDragNode({ id: 1 }, { ...ctxOn, dragGateOn: false })).toEqual({ ok: false, reason: '' })
  })
  it('確認框開著或請求未回（busy）時不可拖、無原因', () => {
    expect(canDragNode({ id: 1 }, { ...ctxOn, busy: true })).toEqual({ ok: false, reason: '' })
  })
  it('帶旗標：move 可用即可拖', () => {
    expect(canDragNode(flagged({ can_move: true }), ctxOn)).toEqual({ ok: true, reason: '' })
  })
  it('帶旗標：範圍根停用，原因為 scopeRootLocked', () => {
    const r = canDragNode(flagged({ can_move: false, scope_root: true }), ctxOn)
    expect(r).toEqual({ ok: false, reason: 'nodeTree.scopeRootLocked' })
  })
  it('帶旗標：可管理但限超級管理者，原因為 superAdminOnly', () => {
    const r = canDragNode(flagged({ can_move: false, manageable: true }), ctxOn)
    expect(r).toEqual({ ok: false, reason: 'nodeTree.superAdminOnly' })
  })
  it('帶旗標：move 項不顯示（只作路徑的祖先）不可拖、無原因', () => {
    expect(canDragNode(flagged({ can_move: false }), ctxOn)).toEqual({ ok: false, reason: '' })
  })
  it('沒有旗標：看 canManageNodes', () => {
    expect(canDragNode({ id: 1 }, ctxOn).ok).toBe(true)
    expect(canDragNode({ id: 1 }, { ...ctxOn, canManageNodes: false }).ok).toBe(false)
  })
})

describe('dropVerdict', () => {
  const build = () => {
    const kid = mk({ id: 11, name: 'kid', parent_id: 10, can_create_child: true }, { level: 2, loaded: true })
    const dragging = mk({ id: 10, name: 'web', parent_id: 1 }, { level: 2, children: [kid] })
    const parent = mk({ id: 1, name: 'prod', can_create_child: true }, { level: 1 })
    const other = mk({ id: 2, name: 'stg', can_create_child: true }, { level: 1, loaded: true })
    return { dragging, kid, parent, other }
  }
  it('source：放在自己身上', () => {
    const { dragging } = build()
    expect(dropVerdict(dragging, dragging, ctxOn).code).toBe('source')
  })
  it('self：放在已載入的子孫身上', () => {
    const { dragging, kid } = build()
    expect(dropVerdict(dragging, kid, ctxOn).code).toBe('self')
  })
  it('already：放回原父節點', () => {
    const { dragging, parent } = build()
    expect(dropVerdict(dragging, parent, ctxOn).code).toBe('already')
  })
  it('noPermission：帶旗標且 can_create_child 不為 true；不帶旗標看 canManageNodes', () => {
    const { dragging } = build()
    const x = mk({ id: 3, name: 'x', can_rename: true, can_create_child: false }, { level: 1 })
    expect(dropVerdict(dragging, x, ctxOn).code).toBe('noPermission')
    const y = mk({ id: 4, name: 'y' }, { level: 1 })
    expect(dropVerdict(dragging, y, { ...ctxOn, canManageNodes: false }).code).toBe('noPermission')
  })
  it('depth：目標已在第 10 層', () => {
    const { dragging } = build()
    const deep = mk({ id: 5, name: 'deep', can_create_child: true }, { level: 10 })
    expect(dropVerdict(dragging, deep, ctxOn).code).toBe('depth')
  })
  it('sameName：已載入目標有同名且不同 id；區分大小寫', () => {
    const { dragging } = build()
    const dup = mk({ id: 99, name: 'web' }, { level: 2 })
    const t1 = mk({ id: 6, name: 't', can_create_child: true }, { level: 1, loaded: true, children: [dup] })
    expect(dropVerdict(dragging, t1, ctxOn).code).toBe('sameName')
    const upper = mk({ id: 98, name: 'WEB' }, { level: 2 })
    const t2 = mk({ id: 7, name: 't2', can_create_child: true }, { level: 1, loaded: true, children: [upper] })
    expect(dropVerdict(dragging, t2, ctxOn).code).toBe('ok')
  })
  it('目標未載入時不判同名', () => {
    const { dragging } = build()
    const dup = mk({ id: 99, name: 'web' }, { level: 2 })
    const t = mk({ id: 8, name: 't', can_create_child: true }, { level: 1, loaded: false, children: [dup] })
    expect(dropVerdict(dragging, t, ctxOn).code).toBe('ok')
  })
  it('ok：其餘', () => {
    const { dragging, other } = build()
    expect(dropVerdict(dragging, other, ctxOn)).toEqual({ code: 'ok', ok: true })
  })
  it('次序：原父節點且無權限＝already；無權限且第 10 層＝noPermission', () => {
    const { dragging } = build()
    const parentNoPerm = mk({ id: 1, name: 'prod', can_rename: true, can_create_child: false }, { level: 1 })
    expect(dropVerdict(dragging, parentNoPerm, ctxOn).code).toBe('already')
    const deepNoPerm = mk({ id: 9, name: 'd', can_rename: true, can_create_child: false }, { level: 10 })
    expect(dropVerdict(dragging, deepNoPerm, ctxOn).code).toBe('noPermission')
  })
  it('範圍根名稱：找得到與找不到', () => {
    const root = mk({ id: 100, name: 'db-oracle-cluster-01', scope_root: true }, { level: 1 })
    const child = mk({ id: 101, name: 'c', parent_id: 100 }, { level: 2, parent: root })
    const x = mk({ id: 3, name: 'x', can_rename: true, can_create_child: false }, { level: 1 })
    expect(dropVerdict(child, x, ctxOn).scopeName).toBe('db-oracle-cluster-01')
    const lone = mk({ id: 102, name: 'lone', parent_id: 50 }, { level: 1, parent: { level: 0 } })
    expect(dropVerdict(lone, x, ctxOn).scopeName).toBe('')
  })
})

describe('captureOrigin', () => {
  it('記下父、下一個兄弟與展開狀態；根層父為 null', () => {
    const root = { level: 0 }
    const next = mk({ id: 20 }, { level: 1 })
    const node = mk({ id: 10 }, { level: 1, parent: root })
    node.nextSibling = next
    node.expanded = true
    expect(captureOrigin(node)).toEqual({ id: 10, parentKey: null, nextKey: 20, expanded: true })
  })
})

describe('selectionFollows', () => {
  it('選取本身被搬', () => expect(selectionFollows(5, 5, [1, 2])).toBe(true))
  it('選取的祖先被搬', () => expect(selectionFollows(2, 5, [1, 2])).toBe(true))
  it('選取的兄弟被搬', () => expect(selectionFollows(7, 5, [1, 2])).toBe(false))
  it('選取全部資產或未分組', () => {
    expect(selectionFollows(5, null, [])).toBe(false)
    expect(selectionFollows(5, 'ungrouped', [])).toBe(false)
  })
})

describe('compareByCodePoint', () => {
  it('依碼位排序，與資料庫碼位排序一致', () => {
    const list = ['生產', '測試', '歸檔', '深1', 'b', 'B', 'a', 'Z']
    expect([...list].sort(compareByCodePoint)).toEqual(['B', 'Z', 'a', 'b', '歸檔', '深1', '測試', '生產'])
  })
})

describe('classifyMoveError', () => {
  it('有回應的 400/403/404/409/500 為被拒', () => {
    for (const status of [400, 403, 404, 409, 500]) {
      expect(classifyMoveError({ response: { status } })).toBe('rejected')
    }
  })
  it('無回應、502、504 為結果未知', () => {
    expect(classifyMoveError(new Error('Network Error'))).toBe('unknown')
    expect(classifyMoveError({ response: { status: 502 } })).toBe('unknown')
    expect(classifyMoveError({ response: { status: 504 } })).toBe('unknown')
  })
})

describe('版面計算', () => {
  const container = { top: 100, bottom: 500, left: 0, right: 240 }
  it('說明框放在該列右側：左緣不小於樹欄右緣、頂端對齊該列', () => {
    const r = placeTip({ row: { top: 200, bottom: 224 }, container, cursorX: 235, viewport: { width: 1200, height: 800 } })
    expect(r.side).toBe('right')
    expect(r.left).toBeGreaterThanOrEqual(240)
    expect(r.top).toBe(200)
  })
  it('靠下緣時垂直夾在視窗內，仍在樹欄右側', () => {
    const r = placeTip({ row: { top: 770, bottom: 794 }, container, cursorX: 100, viewport: { width: 1200, height: 800 } })
    expect(r.side).toBe('right')
    expect(r.left).toBeGreaterThanOrEqual(240)
    expect(r.top + 84).toBeLessThanOrEqual(800 - 8)
  })
  it('視窗右側放不下才退回列下方，水平夾在樹欄位內', () => {
    const r = placeTip({ row: { top: 200, bottom: 224 }, container, cursorX: 235, viewport: { width: 400, height: 800 } })
    expect(r.side).toBe('below')
    expect(r.top).toBe(226)
    expect(r.left).toBeGreaterThanOrEqual(0)
    expect(r.left).toBeLessThanOrEqual(240 - 204)
  })
  it('邊緣捲動觸發區取樹欄位、捲動容器與視窗的交集', () => {
    expect(visibleScrollRect({ top: 100, bottom: 900 }, { top: 60, bottom: 700 }, 600)).toEqual({ top: 100, bottom: 600 })
    expect(visibleScrollRect({ top: -50, bottom: 300 }, null, 800)).toEqual({ top: 0, bottom: 300 })
  })
  it('確認框靠右緣改放左側、靠下緣夾在視窗內', () => {
    const r = placeConfirm({ row: { top: 700, bottom: 724, left: 900, right: 1100 }, viewport: { width: 1200, height: 760 } })
    expect(r.side).toBe('left')
    expect(r.left + 360).toBeLessThanOrEqual(1200)
    expect(r.top + 340).toBeLessThanOrEqual(760)
  })
  it('邊緣捲動速度：近下緣為正且不超過上限，邊緣區外為 0，近上緣為負', () => {
    const rect = { top: 0, bottom: 400 }
    const near = edgeScrollDelta(390, rect)
    expect(near).toBeGreaterThan(0)
    expect(near).toBeLessThanOrEqual(EDGE_SCROLL_MAX_PX)
    expect(edgeScrollDelta(400 - 40, rect)).toBe(0)
    expect(edgeScrollDelta(5, rect)).toBeLessThan(0)
    expect(EDGE_SCROLL_ZONE_PX).toBe(32)
  })
  it('常數', () => {
    expect(AUTO_EXPAND_MS).toBe(700)
    expect(FLASH_MS).toBe(2000)
  })
})

describe('buildMoveOptions', () => {
  it('根層與子層依原始名稱逐碼位排序，排除自身與子樹', () => {
    const flat = [
      { id: 1, name: '生產', path: '生產', parent_id: null },
      { id: 2, name: '測試', path: '測試', parent_id: null },
      { id: 3, name: '歸檔', path: '歸檔', parent_id: null },
      { id: 4, name: 'b', path: '歸檔 / b', parent_id: 3 },
      { id: 5, name: 'B', path: '歸檔 / B', parent_id: 3 },
      { id: 6, name: 'self', path: 'self', parent_id: null },
      { id: 7, name: 'sub', path: 'self / sub', parent_id: 6 },
    ]
    const opts = buildMoveOptions(flat, 6)
    expect(opts.map((o) => o.rawName)).toEqual(['歸檔', '測試', '生產'])
    expect(opts[0].children.map((o) => o.rawName)).toEqual(['B', 'b'])
    expect(JSON.stringify(opts)).not.toContain('sub')
  })
})
