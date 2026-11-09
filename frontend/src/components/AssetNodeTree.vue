<template>
  <!-- 資產節點樹：左樹導覽＋節點 CRUD＋授權入口。
       惰性載入（點展開才拉子層）；「全部資產」與「未分組」為虛擬項不入庫 -->
  <div
    ref="rootRef"
    class="asset-node-tree"
    @dragover.capture="drag.onContainerDragOver"
  >
    <NodeTreeDragOverlays
      :hint="drag.dragging.value && dragGateOn"
      :tip="dragGateOn ? drag.tip.value : null"
      :row-tip="drag.rowTip.value"
      :locked="flow.confirm.value.visible && flow.confirm.value.phase === 'moving'"
      :lock-height="lockHeight"
      :cover-height="coverHeight"
    />
    <div
      ref="headerRef"
      class="tree-header"
    >
      <span
        class="tree-title all-assets"
        :class="{ active: selectedKey === null }"
        role="button"
        tabindex="0"
        @click="selectAll"
        @keydown.enter.space.prevent="selectAll"
      >{{ $t('nodeTree.allAssets') }}<span
        v-if="counts.all !== null"
        class="node-count"
      >{{ counts.all }}</span></span>
      <el-button
        v-if="showCreateRoot"
        v-preview-write:create
        link
        type="primary"
        size="small"
        class="create-root-btn"
        @click="openCreate(null)"
      >
        <el-icon><Plus /></el-icon>
        {{ $t('nodeTree.rootNode') }}
      </el-button>
    </div>

    <el-tree
      ref="treeRef"
      :key="treeKey"
      lazy
      :load="loadChildren"
      :props="treeProps"
      node-key="id"
      highlight-current
      :indent="12"
      :expand-on-click-node="false"
      :draggable="dragGateOn"
      :allow-drag="allowDrag"
      :allow-drop="allowDrop"
      @node-click="selectNode"
      @node-drag-start="drag.onDragStart"
      @node-drag-over="drag.onDragOver"
      @node-drag-leave="drag.onDragLeave"
      @node-drag-end="drag.stopDrag"
      @node-drop="flow.onDrop"
    >
      <template #default="{ node, data }">
        <div
          class="tree-node-row"
          :class="drag.rowClass(data, flashId)"
          @mouseenter="drag.onRowEnter($event, node, data)"
          @mouseleave="drag.onRowLeave"
        >
          <span
            v-if="canDragNode(data, dragCtx).ok"
            class="drag-handle"
            aria-hidden="true"
            @mouseenter="drag.onHandleEnter($event, node, data)"
            @mouseleave="drag.onRowLeave"
          ><GripVertical :size="12" /></span>
          <span
            v-else
            class="drag-handle-slot"
            aria-hidden="true"
          />
          <span class="node-label">
            {{ data.name }}
            <span
              v-if="data.scope_root === true"
              class="scope-badge"
            >{{ $t('nodeTree.scopeBadge') }}</span>
            <span
              v-if="movedTagId !== data.id"
              class="node-count"
            >{{ data.subtree_asset_count }}</span>
          </span>
          <span
            v-if="movedTagId === data.id"
            class="moved-tag"
          >{{ $t('nodeTree.movedTag') }}</span>
          <el-dropdown
            v-if="showMenu(data)"
            trigger="click"
            class="node-menu"
            @command="(cmd) => handleMenu(cmd, data)"
            @visible-change="drag.onMenuVisible"
          >
            <el-icon
              class="node-menu-trigger"
              @click.stop
            >
              <Ellipsis />
            </el-icon>
            <template #dropdown>
              <el-dropdown-menu>
                <PreviewDropdownItem
                  v-if="itemState(data, 'create-child').visible"
                  command="create-child"
                  :disabled="itemState(data, 'create-child').disabled"
                >
                  {{ $t('nodeTree.createChild') }}
                </PreviewDropdownItem>
                <PreviewDropdownItem
                  v-if="itemState(data, 'rename').visible"
                  command="rename"
                  :disabled="itemState(data, 'rename').disabled"
                >
                  {{ $t('common.rename') }}
                  <span
                    v-if="itemState(data, 'rename').reason"
                    class="item-reason"
                  >{{ $t(itemState(data, 'rename').reason) }}</span>
                </PreviewDropdownItem>
                <PreviewDropdownItem
                  v-if="itemState(data, 'move').visible"
                  command="move"
                  :disabled="itemState(data, 'move').disabled"
                >
                  {{ $t('nodeTree.move') }}
                  <span
                    v-if="itemState(data, 'move').reason"
                    class="item-reason"
                  >{{ $t(itemState(data, 'move').reason) }}</span>
                </PreviewDropdownItem>
                <el-dropdown-item
                  v-if="canAuthorizeNodes"
                  command="authorize"
                  :disabled="!canAuthorizeNode(data)"
                >
                  {{ $t('nodeTree.authorizeNode') }}
                  <span
                    v-if="!canAuthorizeNode(data)"
                    class="item-reason"
                  >{{ $t('nodeTree.authorizeNodeUnavailable') }}</span>
                </el-dropdown-item>
                <PreviewDropdownItem
                  v-if="itemState(data, 'delete').visible"
                  command="delete"
                  :disabled="itemState(data, 'delete').disabled"
                  divided
                >
                  {{ $t('common.delete') }}
                  <span
                    v-if="itemState(data, 'delete').reason"
                    class="item-reason"
                  >{{ $t(itemState(data, 'delete').reason) }}</span>
                </PreviewDropdownItem>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </template>
    </el-tree>

    <!-- 「其他」區塊：未分組獨立於節點樹之外（分隔線＋小節標題強化存在感，
         走查實證純文字尾行易被忽略） -->
    <div class="tree-section">
      <div class="tree-section-title">
        {{ $t('nodeTree.sectionOther') }}
      </div>
      <div
        class="ungrouped-item"
        :class="{ active: selectedKey === 'ungrouped' }"
        role="button"
        tabindex="0"
        @click="selectUngrouped"
        @keydown.enter.space.prevent="selectUngrouped"
      >
        {{ $t('assets.ungrouped') }}
        <span
          v-if="counts.ungrouped !== null"
          class="node-count"
        >{{ counts.ungrouped }}</span>
      </div>
    </div>

    <!-- 建立/改名對話框 -->
    <el-dialog
      v-model="editVisible"
      :title="editDialogTitle"
      width="420px"
      append-to-body
    >
      <el-form
        label-position="top"
        @submit.prevent
      >
        <el-form-item :label="$t('common.name')">
          <el-input
            v-model="editName"
            maxlength="100"
            :placeholder="$t('nodeTree.namePlaceholder')"
          />
        </el-form-item>
        <el-form-item :label="$t('common.description')">
          <el-input
            v-model="editDescription"
            maxlength="500"
            :placeholder="$t('nodeTree.descPlaceholder')"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="saving"
          :disabled="!editName.trim()"
          @click="submitEdit"
        >
          {{ $t('common.confirm') }}
        </el-button>
      </template>
    </el-dialog>

    <!-- 搬移對話框：目標父節點樹選（清空＝搬到根層） -->
    <el-dialog
      v-model="moveVisible"
      :title="$t('nodeTree.moveTitle', { name: moveTarget?.name || '' })"
      width="420px"
      append-to-body
    >
      <el-form label-position="top">
        <el-form-item :label="$t('nodeTree.moveTargetLabel')">
          <el-tree-select
            v-model="moveParentId"
            :data="moveOptions"
            :props="{ label: 'name', children: 'children' }"
            node-key="id"
            check-strictly
            :clearable="allowRootMove"
            :placeholder="$t('nodeTree.movePlaceholder')"
            style="width: 100%"
          />
          <div
            v-if="moveSameParent"
            class="move-already-here"
          >
            {{ $t('nodeTree.moveAlreadyHere', { target: moveParentPath }) }}
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="moveVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="saving"
          :disabled="(!allowRootMove && !moveParentId) || moveSameParent"
          @click="submitMove"
        >
          {{ $t('common.confirm') }}
        </el-button>
      </template>
    </el-dialog>

    <NodeMoveConfirmDialog
      :visible="flow.confirm.value.visible"
      :phase="flow.confirm.value.phase"
      :node-name="flow.confirm.value.name"
      :from-path="flow.confirm.value.fromPath"
      :to-path="flow.confirm.value.toPath"
      :count="flow.confirm.value.count"
      :anchor="flow.confirm.value.anchor"
      :reject-head="flow.confirm.value.head"
      :reject-reason="flow.confirm.value.reason"
      :reject-next="flow.confirm.value.next"
      @confirm="flow.onConfirm"
      @cancel="flow.onCancel"
      @ack="flow.onAck"
    />

    <NodeDeleteBlockedDialog
      v-model="blockedVisible"
      :path="blockedInfo.path"
      :count="blockedInfo.count"
      :references="blockedInfo.references"
    />
  </div>
</template>

<script setup>
import PreviewDropdownItem from '@/components/PreviewDropdownItem.vue'
import { ref, computed, nextTick, onMounted, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Ellipsis, GripVertical } from 'lucide-vue-next'
import '@/components/node-tree-drag.css'
import { t } from '@/i18n'
import { can } from '@/composables/useCapabilities'
import { previewWrite as vPreviewWrite } from '@/directives/previewWrite'
import {
  hasRowFlags,
  hasAnyAction,
  scopedActionStates,
} from '@/composables/useNodeTreeScope'
import {
  buildMoveOptions,
  canDragNode,
  dropVerdict,
} from '@/composables/useNodeTreeDrag'
import { useNodeTreeMove, useFlash } from '@/composables/useNodeTreeMove'
import { useNodeTreeDragUi } from '@/composables/useNodeTreeDragUi'
import { useNodeTreeMoveFlow } from '@/composables/useNodeTreeMoveFlow'
import NodeDeleteBlockedDialog from '@/components/NodeDeleteBlockedDialog.vue'
import NodeMoveConfirmDialog from '@/components/NodeMoveConfirmDialog.vue'
import NodeTreeDragOverlays from '@/components/NodeTreeDragOverlays.vue'
import { getAuthorizationTargetOptions } from '@/api/authorizations'
import { isSelectableNode, loadSelector } from '@/utils/authzSelectors'
import {
  getAssetList,
  getAssetNodeTree,
  getAssetGroups,
  createAssetGroup,
  updateAssetGroup,
  deleteAssetGroup,
} from '@/api/assets'

const props = defineProps({
  // 承載頁停用節點拖拉（例如角色預覽中）；「⋯」選單與搬移對話框不受影響
  nodeDragDisabled: { type: Boolean, default: false },
})

// 節點操作依各自的後端能力顯示（不以單一「可管理」包住全部動作）：
// 新增／改名／移動／刪除節點＝assetgroup:manage；跳去授權頁＝authorization:manage
const canManageNodes = computed(() => can('assetgroup:manage'))
const canAuthorizeNodes = computed(() => can('authorization:manage'))

// 根層建立與搬到根層：範圍化檢視者的根層回應附 can_create_root，以它為準；
// 回應沒有這個欄位（非範圍化檢視者）時沿用 canManageNodes。尚未載入前同樣沿用
const rootCanCreate = ref(null)
const showCreateRoot = computed(() =>
  typeof rootCanCreate.value === 'boolean' ? rootCanCreate.value : canManageNodes.value
)
const allowRootMove = computed(() => rootCanCreate.value !== false)

// 選單項目的呈現：節點帶旗標時逐項依 can_*，否則沿用 canManageNodes
const LEGACY_ITEMS = ['create-child', 'rename', 'move', 'delete']
const itemState = (node, command) => {
  if (hasRowFlags(node)) return scopedActionStates(node)[command]
  const on = canManageNodes.value && LEGACY_ITEMS.includes(command)
  return { visible: on, disabled: false, reason: '' }
}
// 帶旗標的節點，四項動作旗標皆 false 時不顯示選單（manageable=false 本身不隱藏）
const showMenu = (node) =>
  hasRowFlags(node)
    ? hasAnyAction(node) || canAuthorizeNodes.value
    : canManageNodes.value || canAuthorizeNodes.value

// 「授權此節點」只對節點候選中可授權的節點啟用：可不可授權只認授權選擇器回的 selectable，
// 其他節點（祖先定位節點、候選之外、候選尚未載入或載入失敗）停用並說明
const authorizableNodeIds = ref(new Set())
const loadAuthorizableNodes = async () => {
  if (!canAuthorizeNodes.value) return
  const res = await loadSelector(getAuthorizationTargetOptions, { kind: 'node' })
  authorizableNodeIds.value = new Set(res.rows.filter(isSelectableNode).map((n) => n.id))
}
const canAuthorizeNode = (node) => authorizableNodeIds.value.has(node?.id)

// select payload：null＝全部、'ungrouped'＝未分組、物件＝節點（含 id/name/path）
const emit = defineEmits(['select', 'authorize'])

const treeKey = ref(0)
const selectedKey = ref(null)
const saving = ref(false)

const treeProps = {
  label: 'name',
  isLeaf: (data) => !data.has_children,
}

const treeRef = ref(null)
const rootRef = ref(null)
const lockHeight = ref(0)
const headerRef = ref(null)
// 標題列（含下方間距）的高度：樹頂提示與鎖定條要完整蓋住它
const coverHeight = ref(0)
const measureCover = () => {
  const el = headerRef.value
  if (el) coverHeight.value = el.offsetHeight + (parseFloat(getComputedStyle(el).marginBottom) || 0)
}
let rootWaiter = null
let moveApi = null

// 子層載入失敗時呼叫元件庫的 reject：節點保持未載入、可再展開重試；根層沒有箭頭可重試，沿用空子層
const loadChildren = async (node, resolve, reject) => {
  const isRoot = node.level === 0
  try {
    const parentId = isRoot ? null : node.data.id
    const quiet = !isRoot && moveApi?.isAwaited(node.data.id)
    const res = quiet ? await getAssetNodeTree(parentId, { skipErrorToast: true }) : await getAssetNodeTree(parentId)
    // 根層回應的頂層欄位（can_create_root）要留下，不能只取 res.data
    if (isRoot) {
      rootCanCreate.value = typeof res.can_create_root === 'boolean' ? res.can_create_root : null
    }
    resolve(res.data || [])
    if (!isRoot) moveApi?.settleLoad(node.data.id, true)
  } catch (error) {
    console.error('載入節點樹失敗:', error)
    if (isRoot || typeof reject !== 'function') resolve([])
    else reject()
    if (!isRoot) moveApi?.settleLoad(node.data.id, false)
  } finally {
    if (isRoot && rootWaiter) {
      rootWaiter()
      rootWaiter = null
    }
  }
}

// 「全部資產／未分組」計數：資產列表端點伺服端已按角色收斂可視範圍，
// 非特權使用者的計數天然不含未授權資產
const counts = ref({ all: null, ungrouped: null })
const loadCounts = async () => {
  try {
    const [allRes, ungroupedRes] = await Promise.all([
      getAssetList({ page: 1, page_size: 1 }),
      getAssetList({ page: 1, page_size: 1, ungrouped: true }),
    ])
    counts.value = { all: allRes.total ?? 0, ungrouped: ungroupedRes.total ?? 0 }
  } catch (error) {
    console.error('載入資產計數失敗:', error)
  }
}
onMounted(() => {
  void loadCounts()
  void loadAuthorizableNodes()
})
// 直接開啟或重新整理頁面時，掛載早於能力載入：能力到齊後再取一次候選
watch(canAuthorizeNodes, (on) => {
  if (on) void loadAuthorizableNodes()
})

const reloadTree = () => {
  treeKey.value += 1
  void loadCounts()
  void loadAuthorizableNodes()
}
// 整樹重載並等根層載入結束（定位用）
const reloadTreeAndWait = () => {
  const done = new Promise((resolve) => {
    rootWaiter = resolve
  })
  reloadTree()
  return done
}
// 外部（預覽範圍選擇器）選定節點時只同步左樹的選中樣式，不再發出 select
// 外部指定選取（預覽範圍）：標亮節點，並依 chain（由根到父的 id）逐層展開到它
const highlight = async (data, chain = []) => {
  const none = data === null || data === undefined
  selectedKey.value = none ? null : data === 'ungrouped' ? 'ungrouped' : data.id
  const tree = treeRef.value
  if (!tree) return
  if (none || data === 'ungrouped') {
    tree.setCurrentKey(null)
    return
  }
  try {
    for (const cid of chain) await move.ensureExpanded(cid)
  } catch {
    // 祖先載入失敗：仍標亮能找到的部分
  }
  if (selectedKey.value !== data.id || !tree.getNode(data.id)) return
  tree.setCurrentKey(data.id)
  await nextTick()
  rootRef.value?.querySelector?.('.el-tree-node.is-current')?.scrollIntoView?.({ block: 'nearest' })
}

defineExpose({ reloadTree, highlight })

const { flashId, movedTagId, flash } = useFlash(rootRef)

// 拖曳：能不能拖／放、列呈現、放下後的流程
const dragGateOn = computed(() => !props.nodeDragDisabled && canManageNodes.value)
const dragCtx = computed(() => ({
  dragGateOn: dragGateOn.value,
  canManageNodes: canManageNodes.value,
  busy: busy.value,
}))
const allowDrag = (n) => canDragNode(n.data, dragCtx.value).ok
const allowDrop = (d, n, type) => type === 'inner' && dropVerdict(d, n, dragCtx.value).ok
const move = useNodeTreeMove({ treeRef, selectedKey, emit, flash, loadCounts, loadAuthorizableNodes })
moveApi = move
const drag = useNodeTreeDragUi({
  treeRef,
  rootRef,
  selectedKey,
  ctx: dragCtx,
  ensureExpanded: move.ensureExpanded,
})
const flow = useNodeTreeMoveFlow({
  treeRef,
  rootRef,
  selectedKey,
  dragInfo: drag.dragInfo,
  move,
  flash,
  selectAll: () => selectAll(),
  reloadTreeAndWait,
})
const busy = computed(() => flow.busy.value)
watch(
  () => flow.confirm.value.phase === 'moving',
  (on) => {
    if (on) lockHeight.value = rootRef.value?.clientHeight || 0
  }
)
watch(() => [drag.dragging.value, flow.confirm.value.phase === 'moving'], ([a, b]) => {
  if (a || b) measureCover()
})
// 停用拖曳：確認中比照取消；已送出者照常完成回應
watch(
  () => props.nodeDragDisabled,
  (off) => {
    if (!off) return
    drag.stopDrag()
    flow.onCancel()
  }
)


const selectAll = () => {
  selectedKey.value = null
  emit('select', null)
}
const selectUngrouped = () => {
  selectedKey.value = 'ungrouped'
  emit('select', 'ungrouped')
}
const selectNode = (data) => {
  selectedKey.value = data.id
  emit('select', data)
}

// 建立/改名
const editVisible = ref(false)
const editMode = ref('create')
const editParent = ref(null) // create 模式的父節點（null＝根）
const editTarget = ref(null) // rename 模式的節點
const editName = ref('')
const editDescription = ref('')

// 對話框標題（computed：切語言即時反映）
const editDialogTitle = computed(() => {
  if (editMode.value === 'rename') return t('nodeTree.renameTitle')
  return editParent.value
    ? t('nodeTree.createChildTitle', { name: editParent.value.name })
    : t('nodeTree.createRootTitle')
})

const openCreate = (parent) => {
  editMode.value = 'create'
  editParent.value = parent
  editName.value = ''
  editDescription.value = ''
  editVisible.value = true
}
const openRename = (node) => {
  editMode.value = 'rename'
  editTarget.value = node
  editName.value = node.name
  editDescription.value = node.description || ''
  editVisible.value = true
}

const submitEdit = async () => {
  saving.value = true
  try {
    if (editMode.value === 'create') {
      await createAssetGroup({
        name: editName.value.trim(),
        description: editDescription.value,
        parent_id: editParent.value ? editParent.value.id : null,
      })
      ElMessage.success(t('nodeTree.created'))
    } else {
      await updateAssetGroup(editTarget.value.id, {
        name: editName.value.trim(),
        description: editDescription.value,
      })
      ElMessage.success(t('nodeTree.updated'))
    }
    editVisible.value = false
    // 改名的是目前選中節點時，重發 select 更新右側提示（path 由後端下次
    // 樹載入刷新；此處就地帶新名稱避免顯示過期）
    if (editMode.value === 'rename' && selectedKey.value === editTarget.value.id) {
      emit('select', { ...editTarget.value, name: editName.value.trim(), path: '' })
    }
    reloadTree()
  } catch (error) {
    console.error('節點儲存失敗:', error)
  } finally {
    saving.value = false
  }
}

// 搬移對話框：目標樹選項用平面列表組裝，排除自身與整個子樹（後端環路檢查仍為硬擋兜底）
const moveVisible = ref(false)
const moveTarget = ref(null)
const moveParentId = ref(null)
const moveOptions = ref([])
const moveFlat = ref([])

// 選的目的與目前父節點相同：不送出，改顯示提示
const moveSameParent = computed(
  () => !!moveTarget.value && (moveParentId.value || null) === (moveTarget.value.parent_id || null)
)
const moveParentPath = computed(() => {
  const pid = moveTarget.value?.parent_id
  const row = pid ? moveFlat.value.find((n) => n.id === pid) : null
  return row ? row.path || row.name : t('nodeTree.allAssets')
})

const openMove = async (node) => {
  moveTarget.value = node
  moveParentId.value = node.parent_id || null
  try {
    const res = await getAssetGroups()
    moveFlat.value = res.data || []
    moveOptions.value = buildMoveOptions(moveFlat.value, node.id)
    moveVisible.value = true
  } catch (error) {
    console.error('載入節點失敗:', error)
  }
}

// 對話框送出：成功與拖曳共用同一套樹更新
const submitMove = async () => {
  saving.value = true
  try {
    const ok = await flow.submitDialogMove(moveTarget.value.id, moveParentId.value || null, moveFlat.value)
    if (ok) moveVisible.value = false
  } catch (error) {
    console.error('搬移後核對失敗:', error)
  } finally {
    saving.value = false
  }
}

// 刪除被管理範圍引用而被擋：超級管理者的回應帶 references，其他持有者只有筆數
const blockedVisible = ref(false)
const blockedInfo = ref({ path: '', count: 0, references: null })
const showBlocked = (node, body) => {
  const count = Number(body?.params?.count)
  blockedInfo.value = {
    path: String(body?.params?.path ?? node.path ?? node.name ?? ''),
    count: Number.isFinite(count) ? count : 0,
    references: Array.isArray(body?.references) ? body.references : null,
  }
  blockedVisible.value = true
}

const handleDelete = async (node) => {
  try {
    await ElMessageBox.confirm(
      t('nodeTree.deleteConfirm', { name: node.name }),
      t('common.deleteConfirmTitle'),
      {
        confirmButtonText: t('common.deleteConfirmButton'),
        cancelButtonText: t('common.cancel'),
        type: 'warning',
      }
    )
  } catch {
    return
  }
  try {
    await deleteAssetGroup(node.id)
    ElMessage.success(t('nodeTree.deleted'))
    if (selectedKey.value === node.id) selectAll()
    reloadTree()
  } catch (error) {
    console.error('刪除節點失敗:', error)
    const body = error?.response?.data
    if (body?.code === 'RULE_NODE_SCOPE_REFERENCED') showBlocked(node, body)
  }
}

const handleMenu = (cmd, data) => {
  switch (cmd) {
    case 'create-child':
      openCreate(data)
      break
    case 'rename':
      openRename(data)
      break
    case 'move':
      void openMove(data)
      break
    case 'authorize':
      emit('authorize', data)
      break
    case 'delete':
      void handleDelete(data)
      break
  }
}
</script>

<style scoped src="./asset-node-tree.css"></style>
