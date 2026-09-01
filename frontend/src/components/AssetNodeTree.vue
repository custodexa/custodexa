<template>
  <!-- 資產節點樹：左樹導覽＋節點 CRUD＋授權入口。
       惰性載入（點展開才拉子層）；「全部資產」與「未分組」為虛擬項不入庫 -->
  <div class="asset-node-tree">
    <div class="tree-header">
      <span
        class="tree-title all-assets"
        :class="{ active: selectedKey === null }"
        @click="selectAll"
      >{{ $t('nodeTree.allAssets') }}<span
        v-if="counts.all !== null"
        class="node-count"
      >{{ counts.all }}</span></span>
      <el-button
        v-if="isAdmin"
        link
        type="primary"
        size="small"
        @click="openCreate(null)"
      >
        <el-icon><Plus /></el-icon>
        {{ $t('nodeTree.rootNode') }}
      </el-button>
    </div>

    <el-tree
      :key="treeKey"
      lazy
      :load="loadChildren"
      :props="treeProps"
      node-key="id"
      highlight-current
      :expand-on-click-node="false"
      @node-click="selectNode"
    >
      <template #default="{ data }">
        <div class="tree-node-row">
          <span class="node-label">
            {{ data.name }}
            <span class="node-count">{{ data.subtree_asset_count }}</span>
          </span>
          <el-dropdown
            v-if="isAdmin"
            trigger="click"
            class="node-menu"
            @command="(cmd) => handleMenu(cmd, data)"
          >
            <el-icon
              class="node-menu-trigger"
              @click.stop
            >
              <Ellipsis />
            </el-icon>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="create-child">
                  {{ $t('nodeTree.createChild') }}
                </el-dropdown-item>
                <el-dropdown-item command="rename">
                  {{ $t('common.rename') }}
                </el-dropdown-item>
                <el-dropdown-item command="move">
                  {{ $t('nodeTree.move') }}
                </el-dropdown-item>
                <el-dropdown-item command="authorize">
                  {{ $t('nodeTree.authorizeNode') }}
                </el-dropdown-item>
                <el-dropdown-item
                  command="delete"
                  divided
                >
                  {{ $t('common.delete') }}
                </el-dropdown-item>
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
        @click="selectUngrouped"
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
            clearable
            :placeholder="$t('nodeTree.movePlaceholder')"
            style="width: 100%"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="moveVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="saving"
          @click="submitMove"
        >
          {{ $t('common.confirm') }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Ellipsis } from 'lucide-vue-next'
import { t } from '@/i18n'
import {
  getAssetList,
  getAssetNodeTree,
  getAssetGroups,
  createAssetGroup,
  updateAssetGroup,
  moveAssetGroup,
  deleteAssetGroup,
} from '@/api/assets'

defineProps({
  isAdmin: { type: Boolean, default: false },
})

// select payload：null＝全部、'ungrouped'＝未分組、物件＝節點（含 id/name/path）
const emit = defineEmits(['select', 'authorize'])

const treeKey = ref(0)
const selectedKey = ref(null)
const saving = ref(false)

const treeProps = {
  label: 'name',
  isLeaf: (data) => !data.has_children,
}

const loadChildren = async (node, resolve) => {
  try {
    const parentId = node.level === 0 ? null : node.data.id
    const res = await getAssetNodeTree(parentId)
    resolve(res.data || [])
  } catch (error) {
    console.error('載入節點樹失敗:', error)
    resolve([])
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
onMounted(loadCounts)

const reloadTree = () => {
  treeKey.value += 1
  loadCounts()
}
defineExpose({ reloadTree })

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

// 搬移：目標樹選項用平面列表組裝，排除自身與整個子樹（子孫是必定
// 失敗的環路目標，不該出現在選項；後端環路檢查仍為硬擋兜底）
const moveVisible = ref(false)
const moveTarget = ref(null)
const moveParentId = ref(null)
const moveOptions = ref([])

const buildMoveOptions = (flat, excludeId) => {
  // 先收集 excludeId 的全部子孫
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
  flat.forEach((n) => {
    if (!excluded.has(n.id)) byId.set(n.id, { id: n.id, name: n.path || n.name, parent_id: n.parent_id, children: [] })
  })
  const roots = []
  byId.forEach((n) => {
    if (n.parent_id && byId.has(n.parent_id)) {
      byId.get(n.parent_id).children.push(n)
    } else {
      roots.push(n)
    }
  })
  return roots
}

const openMove = async (node) => {
  moveTarget.value = node
  moveParentId.value = node.parent_id || null
  try {
    const res = await getAssetGroups()
    moveOptions.value = buildMoveOptions(res.data || [], node.id)
    moveVisible.value = true
  } catch (error) {
    console.error('載入節點失敗:', error)
  }
}

const submitMove = async () => {
  saving.value = true
  try {
    await moveAssetGroup(moveTarget.value.id, moveParentId.value || null)
    ElMessage.success(t('nodeTree.moved'))
    moveVisible.value = false
    // 搬移的是目前選中節點時，路徑已變——回「全部資產」避免過期過濾語境
    if (selectedKey.value === moveTarget.value.id) {
      selectAll()
    }
    reloadTree()
  } catch (error) {
    console.error('搬移失敗:', error)
  } finally {
    saving.value = false
  }
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
      openMove(data)
      break
    case 'authorize':
      emit('authorize', data)
      break
    case 'delete':
      handleDelete(data)
      break
  }
}
</script>

<style scoped>
.asset-node-tree {
  width: 240px;
  flex-shrink: 0;
  border-right: 1px solid var(--ot-border-subtle);
  padding-right: var(--ot-space-sm);
  overflow-y: auto;
}

.tree-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: var(--ot-space-xs);
}

.all-assets {
  cursor: pointer;
  font-weight: 600;
  color: var(--ot-text-primary);
  padding: 4px 8px;
  border-radius: 4px;
}

.all-assets.active,
.ungrouped-item.active {
  background: var(--el-color-primary-light-9);
  color: var(--el-color-primary);
}

.tree-node-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex: 1;
  min-width: 0;
  padding-right: 4px;
}

.node-label {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.node-count {
  color: var(--ot-text-secondary);
  font-size: 12px;
  margin-left: 4px;
}

.node-menu-trigger {
  visibility: hidden;
  cursor: pointer;
  color: var(--ot-text-secondary);
}

.tree-node-row:hover .node-menu-trigger {
  visibility: visible;
}

.tree-section {
  margin-top: var(--ot-space-sm);
  padding-top: var(--ot-space-xs);
  border-top: 1px solid var(--ot-border-subtle);
}

.tree-section-title {
  font-size: 12px;
  color: var(--ot-text-secondary);
  padding: 2px 8px;
}

.ungrouped-item {
  cursor: pointer;
  padding: 6px 8px;
  color: var(--ot-text-primary);
  border-radius: 4px;
}

.ungrouped-item:hover {
  background: var(--el-fill-color-light);
}
</style>
