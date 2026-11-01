// 節點樹搬移後的樹更新：逐層展開、就地插入、資產數與旗標寫回、選取處理、整樹重載後定位。
// 只依賴 el-tree 的實例方法（getNode／remove／insertBefore／append／setCurrentKey），
// 由 AssetNodeTree 以 treeRef 注入。
import { ref, nextTick } from 'vue'
import { getAssetNodeTree, getAssetGroups } from '@/api/assets'
import { FLASH_MS } from '@/composables/useNodeTreeDrag'

// 搬移後的同步讀取失敗由流程自己處理（退回整樹重載），不跳全域提示
const QUIET = { skipErrorToast: true }

// 祖先列要寫回的欄位（資產數有多歸屬去重，不能用加減推算；旗標隨範圍變動）
const REFRESH_FIELDS = [
  'subtree_asset_count',
  'asset_count',
  'has_children',
  'can_create_child',
  'can_rename',
  'can_move',
  'can_delete',
  'manageable',
]

/** 短暫標亮（原位、新位置）；tag＝成功時列尾加「已搬移」 */
export function useFlash(rootRef) {
  const flashId = ref(null)
  const movedTagId = ref(null)
  let timer = null
  const flash = (id, { tag = false } = {}) => {
    clearTimeout(timer)
    flashId.value = id
    movedTagId.value = tag ? id : null
    nextTick(() => {
      rootRef.value?.querySelector?.(`[data-key="${id}"]`)?.scrollIntoView?.({ block: 'nearest' })
    })
    timer = setTimeout(() => {
      flashId.value = null
      movedTagId.value = null
    }, FLASH_MS)
  }
  return { flashId, movedTagId, flash }
}

export function useNodeTreeMove({ treeRef, selectedKey, emit, flash, loadCounts, loadAuthorizableNodes }) {
  // ensureExpanded 的等待表：節點 id → [{ resolve, reject }]
  const waiters = new Map()

  /** loader 結束時呼叫：ok＝子層已載入、否則載入失敗 */
  const settleLoad = (id, ok) => {
    const list = waiters.get(id)
    if (!list) return
    waiters.delete(id)
    list.forEach((w) => (ok ? w.resolve() : w.reject(new Error('load failed'))))
  }

  /** 該節點的子層載入是否正由 ensureExpanded 等待中（此時載入失敗不跳全域提示） */
  const isAwaited = (id) => waiters.has(id)

  /** 展開節點並等待 lazy 載入完成；節點不存在或載入失敗即 reject */
  const ensureExpanded = (id) =>
    new Promise((resolve, reject) => {
      const node = treeRef.value?.getNode(id)
      if (!node) {
        reject(new Error('node missing'))
        return
      }
      if (node.loaded) {
        if (!node.expanded) node.expand()
        resolve()
        return
      }
      const list = waiters.get(id) || []
      list.push({
        resolve: () => {
          const n = treeRef.value?.getNode(id)
          if (n && !n.expanded) n.expand()
          resolve()
        },
        reject,
      })
      waiters.set(id, list)
      node.expand()
    })

  const writeBack = (rows) => {
    const tree = treeRef.value
    for (const row of rows || []) {
      const node = tree.getNode(row.id)
      if (!node) continue
      for (const key of REFRESH_FIELDS) {
        if (key in row) node.data[key] = row[key]
      }
    }
  }

  /**
   * 成功後的就地更新（design 5.1）。oldChain／newChain 是由根到舊父／新父的 id 序列。
   * 任一步失敗即 throw，由呼叫端退回整樹重載。
   */
  const applyMoveSuccess = async ({ id, oldChain, newChain, follows, selectedAncestors = [] }) => {
    const tree = treeRef.value
    const newParentId = newChain.length ? newChain[newChain.length - 1] : null
    const preLoaded = new Set()
    for (const cid of [...oldChain, ...newChain]) {
      if (tree.getNode(cid)?.loaded) preLoaded.add(cid)
    }
    const wasLoaded = newParentId === null ? true : preLoaded.has(newParentId)

    // 1. 先從原位拿掉，避免新父 lazy 載入時同一 id 在樹上出現兩次
    tree.remove(id)

    // 2. 逐層載入並展開目的祖先
    for (const cid of newChain) await ensureExpanded(cid)
    if (newParentId !== null && !tree.getNode(newParentId)) throw new Error('new parent missing')

    // 3. 插入：新父原本已載入才需要自己插；原本未載入者 lazy 載入已含該列
    let row = null
    if (wasLoaded) {
      const res = await getAssetNodeTree(newParentId, QUIET)
      const list = res.data || []
      const idx = list.findIndex((r) => r.id === id)
      if (idx < 0) throw new Error('moved row missing')
      row = list[idx]
      const sibling = list.slice(idx + 1).find((r) => tree.getNode(r.id))
      if (sibling) tree.insertBefore(row, sibling.id)
      else tree.append(row, newParentId)
    }
    const node = tree.getNode(id)
    if (!node) throw new Error('moved node missing')
    const parentOk = newParentId === null ? node.parent?.level === 0 : node.parent?.data?.id === newParentId
    if (!parentOk) throw new Error('moved node under wrong parent')
    row = row || node.data

    // 4. 兩條祖先鏈中搬移前已載入的各層：取回並寫回既有節點
    const levels = new Set()
    for (const chain of [oldChain, newChain]) {
      chain.forEach((_, i) => {
        const parent = i === 0 ? null : chain[i - 1]
        if (parent === null || preLoaded.has(parent)) levels.add(parent)
      })
    }
    for (const parent of levels) {
      const res = await getAssetNodeTree(parent, QUIET)
      writeBack(res.data)
    }

    // 5. 標示新位置（捲入並短暫標亮，列尾顯示「已搬移」）
    flash(id, { tag: true })

    // 6. 選取
    const sel = selectedKey.value
    if (follows) {
      if (sel === id) {
        tree.setCurrentKey(id)
        emit('select', row)
      } else {
        const down = selectedAncestors.slice(selectedAncestors.indexOf(id))
        for (const cid of down) await ensureExpanded(cid)
        const res = await getAssetNodeTree(down[down.length - 1], QUIET)
        const selRow = (res.data || []).find((r) => r.id === sel)
        if (!selRow) throw new Error('selected row missing')
        tree.setCurrentKey(sel)
        emit('select', selRow)
      }
    } else if (sel !== null && sel !== 'ungrouped' && (oldChain.includes(sel) || newChain.includes(sel))) {
      const n = tree.getNode(sel)
      if (n) emit('select', n.data)
    }

    // 7. 計數與可授權節點（失敗只記 console）
    loadCounts()
    Promise.resolve(loadAuthorizableNodes()).catch((e) => console.error('載入可授權節點失敗:', e))
    return row
  }

  /** 整樹重載後依平面列表的父鏈逐層展開並標亮；任一步失敗就停在根層，不顯示訊息 */
  const locateAfterReload = async (id) => {
    try {
      const res = await getAssetGroups(undefined, { skipErrorToast: true })
      const byId = new Map((res.data || []).map((n) => [n.id, n]))
      const me = byId.get(id)
      if (!me) return
      const chain = []
      let cur = me.parent_id
      while (cur != null && byId.has(cur) && chain.length < 64) {
        chain.unshift(cur)
        cur = byId.get(cur).parent_id
      }
      for (const cid of chain) await ensureExpanded(cid)
      if (!treeRef.value?.getNode(id)) return
      flash(id, { tag: false })
    } catch (error) {
      console.error('重載後定位失敗:', error)
    }
  }

  /**
   * 404 後局部重載：取各給定父層的最新子層，不在回應中的節點就地移除。
   * checks＝[{ parentId, ids }]；回傳被移除的 id。取層失敗會 throw（呼叫端退回整樹重載）。
   */
  const pruneMissing = async (checks) => {
    const tree = treeRef.value
    const removed = []
    for (const { parentId, ids } of checks) {
      if (parentId !== null && !tree.getNode(parentId)) continue
      const res = await getAssetNodeTree(parentId, QUIET)
      const present = new Set((res.data || []).map((r) => r.id))
      for (const rid of ids) {
        if (!present.has(rid) && tree.getNode(rid)) {
          tree.remove(rid)
          removed.push(rid)
        }
      }
    }
    return removed
  }

  return { ensureExpanded, isAwaited, settleLoad, applyMoveSuccess, locateAfterReload, pruneMissing }
}

/** 由 Node 往上收集 id 鏈（根到該節點的父；不含自己） */
export function ancestorIdsOf(node) {
  const ids = []
  let cur = node?.parent
  while (cur && cur.level > 0) {
    ids.unshift(cur.data.id)
    cur = cur.parent
  }
  return ids
}

/** 由平面列表的 parent_id 往上收集 id 鏈（根到該節點的父；不含自己） */
export function ancestorIdsFromFlat(flat, id) {
  const byId = new Map(flat.map((n) => [n.id, n]))
  const ids = []
  let cur = byId.get(id)?.parent_id
  while (cur != null && byId.has(cur) && ids.length < 64) {
    ids.unshift(cur)
    cur = byId.get(cur).parent_id
  }
  return ids
}
