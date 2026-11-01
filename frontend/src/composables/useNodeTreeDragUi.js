// 節點樹拖曳中的互動：說明框、停留自動展開、邊緣自動捲動。
import { ref, onBeforeUnmount } from 'vue'
import { t } from '@/i18n'
import {
  AUTO_EXPAND_MS,
  ROW_TIP_DELAY_MS,
  canDragNode,
  captureOrigin,
  findScopeRootName,
  dropVerdict,
  edgeScrollDelta,
  findScrollParent,
  visibleScrollRect,
  placeTip,
  shouldAutoExpand,
} from '@/composables/useNodeTreeDrag'
import { ancestorIdsOf } from '@/composables/useNodeTreeMove'
import { hasRowFlags } from '@/composables/useNodeTreeScope'

export function useNodeTreeDragUi({ treeRef, rootRef, selectedKey, ctx, ensureExpanded }) {
  const dragging = ref(false)
  const dragSourceId = ref(null)
  const tip = ref(null)
  const hover = ref({ id: null, ok: false })
  // 放下時用：原位置與拖曳開始當下選取節點的上層鏈（放下後樹已改動，拿不到）
  const dragInfo = { origin: null, selectedAncestors: [] }
  let expandTimer = null
  let expandTargetId = null
  let scrollRaf = null
  let pointerY = null

  const clearExpand = () => {
    if (expandTimer) clearTimeout(expandTimer)
    expandTimer = null
    expandTargetId = null
  }

  // 游標移出樹欄位（例如移到右側資產表）：樹欄位收不到事件，改在文件層偵測並清掉記錄的位置
  const onDocumentDragOver = (event) => {
    const box = rootRef.value
    if (box && event.target instanceof Node && box.contains(event.target)) return
    pointerY = null
  }
  const detachDocListener = () => document.removeEventListener('dragover', onDocumentDragOver, true)

  const stopScroll = () => {
    detachDocListener()
    if (scrollRaf) cancelAnimationFrame(scrollRaf)
    scrollRaf = null
    pointerY = null
  }

  onBeforeUnmount(detachDocListener)

  const stopDrag = () => {
    dragging.value = false
    dragSourceId.value = null
    tip.value = null
    hover.value = { id: null, ok: false }
    clearExpand()
    stopScroll()
  }

  const onDragStart = (node) => {
    if (!ctx.value.dragGateOn) return
    dragInfo.origin = captureOrigin(node)
    const sel = selectedKey.value
    const selNode = typeof sel === 'number' || typeof sel === 'string' ? treeRef.value?.getNode(sel) : null
    dragInfo.selectedAncestors = selNode ? ancestorIdsOf(selNode) : []
    hideRowTip()
    dragging.value = true
    dragSourceId.value = node.data.id
    document.addEventListener('dragover', onDocumentDragOver, true)
  }

  const tipText = (verdict, dragNode, dropNode) => {
    const target = dropNode.data.name
    switch (verdict.code) {
      case 'ok':
        return { title: t('nodeTree.drag.canDropTitle'), body: t('nodeTree.drag.canDropBody', { target }) }
      case 'already':
        return { title: t('nodeTree.drag.alreadyHereTitle'), body: t('nodeTree.drag.alreadyHereBody') }
      case 'self':
        return { title: t('nodeTree.drag.cannotDropTitle'), body: t('nodeTree.drag.reasonSelf') }
      case 'depth':
        return { title: t('nodeTree.drag.cannotDropTitle'), body: t('nodeTree.drag.reasonDepth', { target }) }
      case 'sameName':
        return {
          title: t('nodeTree.drag.cannotDropTitle'),
          body: t('nodeTree.drag.reasonSameName', { name: dragNode.data.name }),
        }
      default: {
        const base = t('nodeTree.drag.reasonNoPermission')
        const scope = verdict.scopeName ? ` ${t('nodeTree.drag.reasonNoPermissionScope', { scope: verdict.scopeName })}` : ''
        return { title: t('nodeTree.drag.cannotDropTitle'), body: base + scope }
      }
    }
  }

  const updateTip = (verdict, dragNode, dropNode, event) => {
    hover.value = { id: dropNode.data.id, ok: verdict.ok }
    if (verdict.code === 'source') {
      tip.value = null
      return
    }
    const rowEl = event?.target?.closest?.('.el-tree-node__content')
    const box = rootRef.value
    if (!rowEl || !box) {
      tip.value = { ...tipText(verdict, dragNode, dropNode), ok: verdict.ok, left: 0, top: 0 }
      return
    }
    const pos = placeTip({ row: rowEl.getBoundingClientRect(), container: box.getBoundingClientRect(), cursorX: event.clientX })
    // 說明卡以視窗座標固定，放在該列右側，不遮樹列也不撐出捲軸
    tip.value = { ...tipText(verdict, dragNode, dropNode), ok: verdict.ok, left: pos.left, top: pos.top }
  }

  const scheduleExpand = (dragNode, dropNode) => {
    if (!shouldAutoExpand(dragNode, dropNode)) {
      clearExpand()
      return
    }
    const id = dropNode.data.id
    if (expandTargetId === id) return
    clearExpand()
    expandTargetId = id
    expandTimer = setTimeout(() => {
      expandTimer = null
      ensureExpanded(id).catch(() => {})
    }, AUTO_EXPAND_MS)
  }

  const onDragOver = (dragNode, dropNode, event) => {
    if (!ctx.value.dragGateOn) return
    const verdict = dropVerdict(dragNode, dropNode, ctx.value)
    updateTip(verdict, dragNode, dropNode, event)
    scheduleExpand(dragNode, dropNode)
  }

  const onDragLeave = () => {
    tip.value = null
    hover.value = { id: null, ok: false }
    clearExpand()
  }

  const scrollStep = () => {
    scrollRaf = null
    const box = rootRef.value
    if (!dragging.value || pointerY === null || !box) return
    // 樹欄位本身不一定是捲動容器：捲最近的可捲動祖先，觸發區是兩者與視窗可見區的交集
    const scroller = findScrollParent(box) || box
    const rect = visibleScrollRect(
      box.getBoundingClientRect(),
      scroller === box ? null : scroller.getBoundingClientRect(),
      window.innerHeight
    )
    const delta = edgeScrollDelta(pointerY, rect)
    if (delta === 0) return
    scroller.scrollTop += delta
    scrollRaf = requestAnimationFrame(scrollStep)
  }

  // 容器層的 dragover：游標停在空白處也能捲
  const onContainerDragOver = (event) => {
    if (!dragging.value || !ctx.value.dragGateOn) return
    pointerY = event.clientY
    if (!scrollRaf) scrollRaf = requestAnimationFrame(scrollStep)
  }

  const rowClass = (data, flashId) => ({
    'is-locator': data.locator_only === true,
    'is-drag-source': dragging.value && dragSourceId.value === data.id,
    'is-drop-no': dragging.value && hover.value.id === data.id && !hover.value.ok,
    'is-flash': flashId === data.id,
  })

  // 停留說明內容：可拖者說明拖法；不能拖且有原因者沿用「⋯」選單同一句
  const rowTipContent = (node, data) => {
    const state = canDragNode(data, ctx.value)
    if (state.ok) {
      const scope = hasRowFlags(data) ? findScopeRootName(node) : ''
      const body = scope ? t('nodeTree.drag.handleBodyScoped', { scope }) : t('nodeTree.drag.handleBody')
      return { title: t('nodeTree.drag.handleTitle'), body }
    }
    if (state.reason) return { title: t('nodeTree.drag.cannotDragTitle'), body: t(state.reason) }
    return data.locator_only === true ? { title: '', body: t('nodeTree.locatorAncestor') } : null
  }

  // 停留說明卡：游標停留片刻後，放在該列右側（視窗放不下才退回列下方）；拖曳中、處理中、選單展開時不顯示。
  // 可拖的列只在游標停在把手上才出現，其餘位置只對「不能拖」與定位用祖先列說明
  const rowTip = ref(null)
  let rowTipTimer = null
  let menuOpen = false
  const hideRowTip = () => {
    if (rowTipTimer) clearTimeout(rowTipTimer)
    rowTipTimer = null
    rowTip.value = null
  }
  const onMenuVisible = (visible) => {
    menuOpen = visible === true
    if (menuOpen) hideRowTip()
  }
  const startRowTip = (event, node, data, { handle }) => {
    hideRowTip()
    if (dragging.value || menuOpen) return
    const content = rowTipContent(node, data)
    const box = rootRef.value
    const rowEl = event?.currentTarget?.closest?.('.el-tree-node__content') || event?.currentTarget
    if (!content || !box || !rowEl) return
    // 「可以拖曳」說明只屬於把手
    if (canDragNode(data, ctx.value).ok !== handle) return
    const clientX = event.clientX ?? 0
    rowTipTimer = setTimeout(() => {
      rowTipTimer = null
      if (dragging.value || menuOpen) return
      const pos = placeTip({ row: rowEl.getBoundingClientRect(), container: box.getBoundingClientRect(), cursorX: clientX })
      rowTip.value = { ...content, ok: true, left: pos.left, top: pos.top }
    }, ROW_TIP_DELAY_MS)
  }
  const onRowEnter = (event, node, data) => startRowTip(event, node, data, { handle: false })
  const onHandleEnter = (event, node, data) => startRowTip(event, node, data, { handle: true })

  return {
    rowClass,
    rowTip,
    onRowEnter,
    onHandleEnter,
    onMenuVisible,
    onRowLeave: hideRowTip,
    dragging,
    dragSourceId,
    tip,
    hover,
    dragInfo,
    stopDrag,
    onDragStart,
    onDragOver,
    onDragLeave,
    onContainerDragOver,
    stopScroll,
  }
}
