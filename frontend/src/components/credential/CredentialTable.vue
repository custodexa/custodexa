<template>
  <div
    class="credential-table"
    data-test="credential-table"
  >
    <el-table
      ref="tableRef"
      v-loading="loading"
      :data="pageRows"
      height="100%"
      row-key="id"
      highlight-current-row
      :current-row-key="selectedId"
      class="table"
      @current-change="onCurrent"
      @selection-change="onSelection"
    >
      <!-- 載入失敗時不說「還沒有任何憑證」：那句話與事實相反，原因由呼叫端就地說明 -->
      <template #empty>
        <EmptyState
          v-if="!loadError"
          :title="t('credentials.emptyTitle')"
          :hint="t('credentials.emptyHint')"
          data-test="credential-empty"
        />
        <span v-else />
      </template>

      <!-- 批次改歸的勾選欄：只有伺服器標示可批次改歸的主體（非範圍化檢視者）才有；專用憑證恆隨資產，不可勾 -->
      <el-table-column
        v-if="batchEnabled"
        type="selection"
        width="44"
        :selectable="isRowSelectable"
        data-test="credential-col-select"
      />

      <!-- 編號＝憑證主鍵：批次匯入資產時 credential_id 欄填的就是它，故放最左、等寬字 -->
      <el-table-column
        prop="id"
        width="88"
        sortable
        data-test="credential-col-id"
      >
        <template #header>
          <el-tooltip
            :content="t('credentials.colIdTooltip')"
            placement="top"
          >
            <span data-test="credential-col-id-header">{{ t('credentials.colId') }}</span>
          </el-tooltip>
        </template>
        <template #default="{ row }">
          <span
            class="mono"
            :data-test="`credential-id-${row.id}`"
          >#{{ row.id }}</span>
        </template>
      </el-table-column>

      <el-table-column
        :label="t('credentials.colName')"
        min-width="130"
        show-overflow-tooltip
      >
        <template #default="{ row }">
          <span
            class="name"
            :class="{ computed: row.scope === 'dedicated' }"
            :data-test="`credential-name-${row.id}`"
          >{{ credentialDisplayName(row) }}</span>
        </template>
      </el-table-column>

      <el-table-column
        :label="t('credentials.colScope')"
        width="72"
      >
        <template #default="{ row }">
          <el-tag
            size="small"
            :type="row.scope === 'shared' ? 'primary' : 'info'"
            :data-test="`credential-scope-${row.id}`"
          >
            {{ t(`enum.credentialScope.${row.scope}`) }}
          </el-tag>
        </template>
      </el-table-column>

      <el-table-column
        :label="t('credentials.colUsername')"
        width="120"
        show-overflow-tooltip
      >
        <template #default="{ row }">
          <span class="mono">{{ row.username }}</span>
        </template>
      </el-table-column>

      <el-table-column
        :label="t('credentials.ownership.label')"
        min-width="130"
        show-overflow-tooltip
      >
        <template #default="{ row }">
          <span :data-test="`credential-ownership-${row.id}`">{{ ownershipText(row) }}</span>
        </template>
      </el-table-column>

      <el-table-column
        :label="t('credentials.colSecretType')"
        width="92"
      >
        <template #default="{ row }">
          {{ secretTypeLabel(row) }}
        </template>
      </el-table-column>

      <el-table-column
        :label="t('credentials.colBindings')"
        width="150"
        align="right"
      >
        <template #default="{ row }">
          <span :data-test="`credential-bindings-${row.id}`">{{ row.binding_count }}</span>
          <!-- 範圍外台數取自伺服器；只給台數，不列名稱 -->
          <span
            v-if="outOfScopeCount(row) > 0"
            class="out-chip"
            :data-test="`credential-out-of-scope-${row.id}`"
          >{{ t('credentials.outOfScopeChip', { count: outOfScopeCount(row) }) }}</span>
        </template>
      </el-table-column>

      <el-table-column
        :label="t('credentials.colRotation')"
        width="106"
      >
        <template #default="{ row }">
          <el-tag
            v-if="row.rotation_active"
            size="small"
            type="primary"
            :data-test="`credential-rotating-${row.id}`"
          >
            {{ t('credentials.stateRotating') }}
          </el-tag>
          <span
            v-else
            class="muted"
          >{{ t('credentials.stateIdle') }}</span>
        </template>
      </el-table-column>

      <el-table-column
        :label="t('credentials.colUpdatedAt')"
        width="140"
      >
        <template #default="{ row }">
          <span class="muted">{{ updatedAtText(row) }}</span>
        </template>
      </el-table-column>

      <el-table-column
        v-if="batchEnabled"
        :label="t('common.actions')"
        width="110"
        data-test="credential-col-actions"
      >
        <template #default="{ row }">
          <el-button
            v-if="row.scope === 'shared'"
            link
            type="primary"
            size="small"
            :data-test="`credential-reassign-${row.id}`"
            @click.stop="emit('reassign', row)"
          >
            {{ t('credentials.reassign.rowAction') }}
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <p
      class="footnote"
      data-test="credential-footnote"
    >
      {{ scopedView ? t('credentials.footer.scoped') : t('credentials.footer.global') }}
    </p>

    <div class="pagination">
      <el-pagination
        :current-page="page"
        :page-size="pageSize"
        :page-sizes="[20, 50, 100]"
        :total="total"
        layout="total, sizes, prev, pager, next, jumper"
        @update:current-page="emit('update:page', $event)"
        @update:page-size="onPageSize"
      />
    </div>
  </div>
</template>

<script setup>
/**
 * 憑證庫左表（設計稿 01 左半）。
 *
 * 顯示名對兩種範圍的來源不同：共用是落庫的名稱，專用是「資產名 / 帳號名」的
 * 計算值——後者以較淡的字重呈現，讓「這一列的名字是系統算出來的、改不了」
 * 在掃視時就看得出來。計算的兩個來源都可能缺席，缺席時由顯示函式補話，
 * 不讓任何一列的名字是空白。
 *
 * 分頁由伺服端切（`page`／`page_size`），總數取自回應。該兩個參數是選用的：
 * 端點未帶時回全部，故本元件在收到超過一頁份量的資料時自行切一頁出來——
 * 兩種回應形狀下畫面都只顯示一頁，不會因為端點回了全部就把整份倒出來。
 */
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import EmptyState from '@/components/EmptyState.vue'
import { formatDateTime } from '@/utils/format'
import { credentialDisplayName } from '@/constants/credentials'
import { outOfScopeCount } from '@/utils/credentialActions'

const props = defineProps({
  credentials: { type: Array, default: () => [] },
  loading: { type: Boolean, default: false },
  // loadError 清單載入失敗：空表要閉嘴，別把失敗說成「沒有資料」
  loadError: { type: Boolean, default: false },
  selectedId: { type: [Number, String], default: null },
  page: { type: Number, default: 1 },
  pageSize: { type: Number, default: 20 },
  total: { type: Number, default: 0 },
  // 範圍化檢視者的視角（伺服器對該主體的列附了 actions）：決定頁尾文案
  scopedView: { type: Boolean, default: false },
  // 顯示勾選欄與列操作欄（批次改歸）；範圍化檢視者沒有
  batchEnabled: { type: Boolean, default: false },
  // 節點識別 → 完整路徑；查不到退回節點編號
  nodePaths: { type: Object, default: () => ({}) },
})

const emit = defineEmits(['select', 'update:page', 'update:pageSize', 'update:selection', 'reassign'])

const { t } = useI18n()

const pageRows = computed(() => {
  if (props.credentials.length <= props.pageSize) return props.credentials
  const start = (props.page - 1) * props.pageSize
  return props.credentials.slice(start, start + props.pageSize)
})

// K8s 的 token 存在密碼欄，值域上仍是 password；顯示層依協定族呈現為 Token，
// 免得畫面上出現一個從來不是密碼的「密碼」
function secretTypeLabel(row) {
  // el-table 量測欄寬時會以空列渲染一次 slot，值域外的輸入不得炸出缺鍵警告
  if (!row?.secret_type) return t('credentials.empty')
  if (row.protocol_family === 'k8s' && row.secret_type === 'password') {
    return t('credentials.secretTypeToken')
  }
  return t(`enum.credentialSecretType.${row.secret_type}`)
}

// 列表只到分鐘：秒數在這裡沒有判斷價值，卻要吃掉一個中文名字的寬度。
// 需要精確到秒的場合在詳情與審計列上
const updatedAtText = (row) => formatDateTime(row.updated_at).slice(0, 16)

function ownershipText(row) {
  const o = row?.ownership
  if (!o) return t('credentials.empty')
  if (o.kind === 'global') return t('credentials.ownership.global')
  if (o.kind === 'asset') return t('credentials.ownership.asset')
  return props.nodePaths[o.node_id] || t('credentials.ownership.nodeRef', { id: o.node_id })
}

const isRowSelectable = (row) => row.scope === 'shared'

function onSelection(rows) {
  emit('update:selection', rows)
}

// 不可命名為 elTable：script setup 會把與元件標籤同名（el-table → elTable）的綁定當成元件解析
const tableRef = ref(null)
// 批次改歸完成或換頁條件變動後，由呼叫端清掉勾選
const clearSelection = () => tableRef.value?.clearSelection?.()
defineExpose({ clearSelection })

function onCurrent(row) {
  if (row) emit('select', row)
}

function onPageSize(size) {
  emit('update:pageSize', size)
  emit('update:page', 1)
}
</script>

<style scoped>
.credential-table {
  display: flex;
  flex-direction: column;
  min-height: 0;
  flex: 1;
}

.table {
  flex: 1;
  min-height: 0;
}

/* 捲動的是表格內容而非整頁：分頁列要一直看得見，否則要換頁得先捲到底 */
.credential-table :deep(.el-table__inner-wrapper) {
  height: 100%;
}

.name {
  font-weight: 500;
}

.name.computed {
  font-weight: 400;
  color: var(--ot-text-secondary);
}

.mono {
  font-family: var(--ot-font-mono);
  font-size: var(--ot-font-size-xs);
}

.muted {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
  white-space: nowrap;
}

.out-chip {
  margin-left: var(--ot-space-xs);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  white-space: nowrap;
}

.footnote {
  margin: 0;
  padding: var(--ot-space-sm) var(--ot-space-md) 0;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.pagination {
  display: flex;
  justify-content: flex-end;
  padding: var(--ot-space-sm) var(--ot-space-md);
  border-top: 1px solid var(--ot-border-subtle);
}
</style>
