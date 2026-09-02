<template>
  <div class="db-console-tree">
    <div class="tree-toolbar">
      <el-input
        v-model="filterText"
        size="small"
        clearable
        :placeholder="t('dbConsole.tree.filterPlaceholder')"
        @input="applyFilter"
      >
        <template #prefix>
          <el-icon><Search /></el-icon>
        </template>
      </el-input>
      <el-button
        size="small"
        text
        :disabled="loading"
        @click="emit('refresh')"
      >
        {{ t('common.refresh') }}
      </el-button>
    </div>

    <div
      v-loading="loading"
      class="tree-body"
    >
      <!-- 兩種空態要分開講：目錄回空是目標端帳號看不到任何庫，
           目錄非空但交集為空是允許清單與目標端名稱對不上（含大小寫） -->
      <EmptyState
        v-if="!loading && !databases.length"
        :title="emptyTitle"
        :hint="emptyHint"
        :icon="DatabaseIcon"
      />
      <el-tree
        v-else
        :key="treeKey"
        ref="treeRef"
        :props="treeProps"
        :load="loadNode"
        :filter-node-method="filterNode"
        lazy
        node-key="id"
        highlight-current
      >
        <template #default="{ data }">
          <span class="tree-node">
            <el-icon class="node-icon">
              <component :is="nodeIcon(data)" />
            </el-icon>
            <!-- title 帶完整限定名：節點文字只留自己那一段，全名要能查得到 -->
            <span
              class="node-label"
              :class="{ 'is-unconnectable': data.connectable === false }"
              :title="data.qualified || data.label"
            >{{ data.label }}</span>
            <el-tooltip
              v-if="data.connectable === false"
              :content="t('dbConsole.tree.unconnectableTip')"
              placement="top"
            >
              <el-icon class="node-lock"><Lock /></el-icon>
            </el-tooltip>
            <span
              v-if="data.typeName"
              class="node-type"
            >{{ data.typeName }}</span>
            <!-- 非當前庫只能切換過去再展開：一條連線同時只在一個庫上 -->
            <el-button
              v-if="data.kind === 'database' && data.name !== currentDatabase"
              link
              type="primary"
              size="small"
              :disabled="data.connectable === false || switching"
              @click.stop="emit('switch', data.name)"
            >
              {{ t('dbConsole.tree.switchTo') }}
            </el-button>
          </span>
        </template>
      </el-tree>

      <p
        v-if="truncated"
        class="tree-truncated"
      >
        {{ t('dbConsole.tree.truncated', { limit: nodeLimit }) }}
      </p>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch, nextTick } from 'vue'
import { Search, Lock, Database as DatabaseIcon, Table2, Columns3 } from 'lucide-vue-next'
import EmptyState from '@/components/EmptyState.vue'
import { t } from '@/i18n'

const props = defineProps({
  // 目錄回傳的資料庫清單（已與允許清單取交集）
  databases: { type: Array, default: () => [] },
  currentDatabase: { type: String, default: '' },
  loading: { type: Boolean, default: false },
  switching: { type: Boolean, default: false },
  truncated: { type: Boolean, default: false },
  nodeLimit: { type: Number, default: 2000 },
  // 資產的允許清單。空態要分成兩種文案，而目錄與清單的交集在伺服端就取完了，
  // 前端唯一能據以分辨的事實就是「這個資產有沒有設允許清單」
  allowedDatabases: { type: Array, default: () => [] },
  // 取得子節點：由父層轉給連線通道，回傳 tree_result
  fetchChildren: { type: Function, required: true },
})

const emit = defineEmits(['switch', 'refresh'])

const treeRef = ref(null)
const filterText = ref('')

const treeProps = { label: 'label', isLeaf: 'isLeaf' }

// 目錄或當前庫換人時整棵重建：lazy 樹的根層由 load 供給，
// 沒有比重建更誠實的方式讓「哪個庫可展開」跟著變
const treeKey = computed(
  () => `${props.currentDatabase}|${props.databases.map((d) => d.name).join(',')}`
)

const hasAllowList = computed(() => props.allowedDatabases.length > 0)
const emptyTitle = computed(() =>
  hasAllowList.value
    ? t('dbConsole.tree.emptyAllowListTitle')
    : t('dbConsole.tree.emptyCatalogTitle')
)
const emptyHint = computed(() =>
  hasAllowList.value
    ? t('dbConsole.tree.emptyAllowListHint')
    : t('dbConsole.tree.emptyCatalogHint')
)

const treeData = computed(() =>
  props.databases.map((db) => ({
    id: `db:${db.name}`,
    kind: 'database',
    name: db.name,
    label: db.name,
    qualified: db.name,
    connectable: db.connectable !== false,
    // 只有當前庫展得開：切庫是一次伺服端動作，不是展開節點的副作用
    isLeaf: db.name !== props.currentDatabase,
  }))
)

// MySQL 的 schema 就是資料庫名，直接串上去會把父節點的名字再唸一次；
// PostgreSQL 與 MSSQL 的 schema 是庫內的另一層，同名表可能分屬不同 schema，那一段要留。
// 判準因此是「這段是不是父層已經說過的名字」，不是方言
function tableLabel(schema, name, database) {
  return schema && schema !== database ? `${schema}.${name}` : name
}

// 完整限定名只進 title：庫、schema、表、欄逐段串起，中間略過與庫同名的 schema
function qualify(database, schema, ...rest) {
  const parts = [database]
  if (schema && schema !== database) parts.push(schema)
  return parts.concat(rest.filter(Boolean)).join('.')
}

function nodeIcon(data) {
  if (data.kind === 'database') return DatabaseIcon
  if (data.kind === 'table') return Table2
  return Columns3
}

// 本地篩選：只過濾已載入的節點，不發任何請求
function applyFilter(value) {
  treeRef.value?.filter(value)
}

function filterNode(value, data) {
  if (!value) return true
  return String(data.label || '').toLowerCase().includes(String(value).toLowerCase())
}

async function loadNode(node, resolve) {
  if (node.level === 0) {
    resolve(treeData.value)
    return
  }
  const data = node.data
  try {
    if (data.kind === 'database') {
      const res = await props.fetchChildren({ level: 'tables' })
      resolve(
        (res?.tables || []).map((tbl) => ({
          id: `tbl:${tbl.schema}.${tbl.name}`,
          kind: 'table',
          name: tbl.name,
          schema: tbl.schema || '',
          label: tableLabel(tbl.schema, tbl.name, data.name),
          qualified: qualify(data.name, tbl.schema, tbl.name),
          typeName: tbl.kind === 'view' ? t('dbConsole.tree.view') : '',
          isLeaf: false,
        }))
      )
      return
    }
    if (data.kind === 'table') {
      const res = await props.fetchChildren({
        level: 'columns',
        schema: data.schema,
        table: data.name,
      })
      resolve(
        (res?.columns || []).map((col) => ({
          id: `col:${data.schema}.${data.name}.${col.name}`,
          kind: 'column',
          name: col.name,
          label: col.name,
          qualified: `${data.qualified}.${col.name}`,
          typeName: col.type_name || '',
          isLeaf: true,
        }))
      )
      return
    }
    resolve([])
  } catch {
    // 載入失敗即收束為空層，讓載入指示停下來；成因已由連線通道的錯誤面板呈現
    resolve([])
  }
}

// 重建後篩選條件仍在輸入框裡，要對新的樹再套一次
watch(treeKey, async () => {
  await nextTick()
  applyFilter(filterText.value)
})
</script>

<style scoped>
.db-console-tree {
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
  border-right: 1px solid var(--el-border-color-lighter);
}

.tree-toolbar {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  padding: var(--ot-space-sm);
  border-bottom: 1px solid var(--el-border-color-lighter);
}

.tree-body {
  flex: 1 1 auto;
  min-height: 0;
  overflow: auto;
  padding: var(--ot-space-xs) 0;
}

/* 樹撐到內容的實際寬度，容器才會出現橫向捲軸；
   壓縮成省略號的話，長表名就只剩 title 查得到 */
.tree-body :deep(.el-tree) {
  min-width: max-content;
}

.tree-node {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
}

.node-icon {
  flex: none;
  color: var(--ot-text-secondary);
}

.node-label {
  white-space: nowrap;
}

.node-label.is-unconnectable {
  color: var(--ot-text-disabled);
}

.node-lock {
  flex: none;
  color: var(--ot-text-disabled);
}

.node-type {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-disabled);
}

.tree-truncated {
  margin: var(--ot-space-xs) var(--ot-space-sm) 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-disabled);
}
</style>
