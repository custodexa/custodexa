<template>
  <div
    class="credential-table"
    data-test="credential-table"
  >
    <el-table
      v-loading="loading"
      :data="pageRows"
      height="100%"
      row-key="id"
      highlight-current-row
      :current-row-key="selectedId"
      class="table"
      @current-change="onCurrent"
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
        :label="t('credentials.colSecretType')"
        width="92"
      >
        <template #default="{ row }">
          {{ secretTypeLabel(row) }}
        </template>
      </el-table-column>

      <el-table-column
        :label="t('credentials.colBindings')"
        width="88"
        align="right"
      >
        <template #default="{ row }">
          <span :data-test="`credential-bindings-${row.id}`">{{ row.binding_count }}</span>
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
    </el-table>

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
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import EmptyState from '@/components/EmptyState.vue'
import { formatDateTime } from '@/utils/format'
import { credentialDisplayName } from '@/constants/credentials'

const props = defineProps({
  credentials: { type: Array, default: () => [] },
  loading: { type: Boolean, default: false },
  // loadError 清單載入失敗：空表要閉嘴，別把失敗說成「沒有資料」
  loadError: { type: Boolean, default: false },
  selectedId: { type: [Number, String], default: null },
  page: { type: Number, default: 1 },
  pageSize: { type: Number, default: 20 },
  total: { type: Number, default: 0 },
})

const emit = defineEmits(['select', 'update:page', 'update:pageSize'])

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

.pagination {
  display: flex;
  justify-content: flex-end;
  padding: var(--ot-space-sm) var(--ot-space-md);
  border-top: 1px solid var(--ot-border-subtle);
}
</style>
