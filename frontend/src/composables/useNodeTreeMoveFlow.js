// 拖曳放下後的流程：還原 → 確認 → 處理中 → 成功／被拒／結果未知／同步失敗。
import { ref, computed } from 'vue'
import { t } from '@/i18n'
import { resolveApiError } from '@/api/error'
import { moveAssetGroup, getAssetGroups } from '@/api/assets'
import { classifyMoveError, rejectKeysFor, selectionFollows } from '@/composables/useNodeTreeDrag'
import { ancestorIdsOf, ancestorIdsFromFlat } from '@/composables/useNodeTreeMove'

const EMPTY = {
  visible: false,
  phase: 'confirm', // confirm｜moving｜reject
  kind: '', // reject 時：rejected｜gone｜unknown
  name: '',
  fromPath: '',
  toPath: '',
  count: 0,
  anchor: null,
  head: '',
  reason: '',
  next: '',
}

export function useNodeTreeMoveFlow({
  treeRef,
  rootRef,
  selectedKey,
  dragInfo,
  move, // useNodeTreeMove 的回傳
  flash,
  selectAll,
  reloadTreeAndWait,
}) {
  const confirm = ref({ ...EMPTY })
  const locating = ref(false)
  const busy = computed(() => confirm.value.visible || locating.value)
  let pending = null

  const close = () => {
    confirm.value = { ...EMPTY }
    pending = null
  }

  const rowRect = (id) => {
    const el = rootRef.value?.querySelector?.(`[data-key="${id}"] .el-tree-node__content`)
    const r = el?.getBoundingClientRect?.()
    return r ? { top: r.top, bottom: r.bottom, left: r.left, right: r.right } : null
  }

  // 元件庫放下時已把節點搬進目標底下；先還原到原位，確認期間樹畫在原位
  const restoreOrigin = (dragNode) => {
    const tree = treeRef.value
    const o = dragInfo.origin
    tree.remove(o.id)
    if (o.nextKey != null && tree.getNode(o.nextKey)) tree.insertBefore(dragNode.data, o.nextKey)
    else tree.append(dragNode.data, o.parentKey)
    if (o.expanded) tree.getNode(o.id)?.expand()
    const sel = selectedKey.value
    if (sel !== null && sel !== 'ungrouped' && tree.getNode(sel)) tree.setCurrentKey(sel)
  }

  const onDrop = (dragNode, dropNode) => {
    const o = dragInfo.origin
    if (!o || !treeRef.value) return
    restoreOrigin(dragNode)
    const tree = treeRef.value
    const restored = tree.getNode(o.id)
    const selectedAncestors = dragInfo.selectedAncestors
    const parentNode = o.parentKey === null ? null : tree.getNode(o.parentKey)
    pending = {
      id: o.id,
      targetId: dropNode.data.id,
      targetName: dropNode.data.name,
      targetParentId: dropNode.parent?.level > 0 ? dropNode.parent.data.id : null,
      sourceParentId: o.parentKey,
      oldChain: restored ? ancestorIdsOf(restored) : o.parentKey === null ? [] : [o.parentKey],
      newChain: [...ancestorIdsOf(dropNode), dropNode.data.id],
      selectedAncestors,
      follows: selectionFollows(o.id, selectedKey.value, selectedAncestors),
    }
    confirm.value = {
      ...EMPTY,
      visible: true,
      name: dragNode.data.name,
      fromPath: parentNode ? parentNode.data.path || parentNode.data.name : '',
      toPath: dropNode.data.path || dropNode.data.name,
      count: Number(dragNode.data.subtree_asset_count) || 0,
      anchor: rowRect(dropNode.data.id),
    }
  }

  // 同步失敗：搬移已在資料庫完成，退回整樹重載並定位；選取跟隨時回「全部資產」
  const syncFail = async (p, error) => {
    console.error('搬移後更新畫面失敗:', error)
    close()
    locating.value = true
    try {
      if (p.follows) selectAll()
      await reloadTreeAndWait()
      await move.locateAfterReload(p.id)
    } finally {
      locating.value = false
    }
  }

  const succeed = async (p) => {
    try {
      await move.applyMoveSuccess(p)
      close()
    } catch (error) {
      await syncFail(p, error)
    }
  }

  const showReject = (kind, head, reason, next) => {
    confirm.value = { ...confirm.value, phase: 'reject', kind, head, reason, next }
  }

  const onMoveError = async (p, error) => {
    if (classifyMoveError(error) === 'rejected') {
      const { status, data } = error.response
      const keys = rejectKeysFor(data?.code)
      showReject(
        data?.code === 'NOTFOUND_ASSET_NODE' ? 'gone' : 'rejected',
        t('nodeTree.moveConfirm.rejectHead'),
        keys ? t(keys.reason, { target: p.targetName }) : resolveApiError(data, status),
        keys ? t(keys.next) : ''
      )
      return
    }
    // 結果未知：先核對實際父層，查到已在目的才算成功；其餘一律不斷定沒有搬移
    try {
      const res = await getAssetGroups(undefined, { skipErrorToast: true })
      const row = (res.data || []).find((n) => n.id === p.id)
      if (row && (row.parent_id ?? null) === p.targetId) {
        await succeed(p)
        return
      }
    } catch (e) {
      console.error('核對搬移結果失敗:', e)
    }
    showReject('unknown', t('nodeTree.moveConfirm.unknownHead'), t('api.networkError'), t('nodeTree.moveConfirm.rejectGoneNext'))
  }

  const onConfirm = async () => {
    const p = pending
    if (!p || confirm.value.phase !== 'confirm') return
    confirm.value = { ...confirm.value, phase: 'moving' }
    try {
      await moveAssetGroup(p.id, p.targetId, { skipErrorToast: true })
    } catch (error) {
      await onMoveError(p, error)
      return
    }
    await succeed(p)
  }

  // 確認中取消（含 Esc、關閉、中途停用）：不送出、原位標亮
  const onCancel = () => {
    if (!confirm.value.visible || confirm.value.phase !== 'confirm') return
    const id = pending?.id
    close()
    if (id != null) flash(id)
  }

  const onAck = async () => {
    const p = pending
    const kind = confirm.value.kind
    close()
    if (!p) return
    if (kind === 'unknown') {
      locating.value = true
      try {
        if (p.follows) selectAll()
        await reloadTreeAndWait()
        await move.locateAfterReload(p.id)
      } finally {
        locating.value = false
      }
      return
    }
    if (kind === 'gone') {
      locating.value = true
      try {
        const sameLevel = p.targetParentId === p.sourceParentId
        const checks = sameLevel
          ? [{ parentId: p.targetParentId, ids: [p.targetId, p.id] }]
          : [
              { parentId: p.targetParentId, ids: [p.targetId] },
              { parentId: p.sourceParentId, ids: [p.id] },
            ]
        const removed = await move.pruneMissing(checks)
        const sel = selectedKey.value
        if (removed.includes(sel) || removed.some((id) => p.selectedAncestors.includes(id))) selectAll()
      } catch (error) {
        console.error('局部重載失敗，改整樹重載:', error)
        await reloadTreeAndWait()
      } finally {
        locating.value = false
      }
    }
    if (treeRef.value?.getNode(p.id)) flash(p.id)
  }

  // 搬移對話框送出：成功與拖曳共用同一套樹更新；被拒維持全域訊息、對話框保持開啟。
  // 回傳 true＝對話框可關閉（含同步失敗已退回整樹重載）
  const submitDialogMove = async (id, newParent, flat) => {
    try {
      await moveAssetGroup(id, newParent)
    } catch (error) {
      console.error('搬移失敗:', error)
      if (error?.response && ![502, 504].includes(error.response.status)) return false
      const res = await getAssetGroups(undefined, { skipErrorToast: true })
      const row = (res.data || []).find((n) => n.id === id)
      if (!row || (row.parent_id ?? null) !== newParent) return false
    }
    const sel = selectedKey.value
    const selectedAncestors = typeof sel === 'number' ? ancestorIdsFromFlat(flat, sel) : []
    const p = {
      id,
      oldChain: ancestorIdsFromFlat(flat, id),
      newChain: newParent === null ? [] : [...ancestorIdsFromFlat(flat, newParent), newParent],
      selectedAncestors,
      follows: selectionFollows(id, sel, selectedAncestors),
    }
    try {
      await move.applyMoveSuccess(p)
    } catch (error) {
      await syncFail(p, error)
    }
    return true
  }

  return { confirm, busy, locating, submitDialogMove, onDrop, onConfirm, onCancel, onAck, syncFail }
}
