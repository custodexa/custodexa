<template>
  <div class="db-console-results">
    <EmptyState
      v-if="!units.length"
      :title="t('dbConsole.results.emptyTitle')"
      :hint="t('dbConsole.results.emptyHint')"
      :icon="TableIcon"
    />

    <template v-else>
      <el-tabs
        :model-value="selection.eventId"
        class="unit-tabs"
        @update:model-value="selectUnit"
      >
        <el-tab-pane
          v-for="unit in units"
          :key="unit.eventId"
          :name="unit.eventId"
        >
          <template #label>
            <span class="unit-label">
              <el-tag
                size="small"
                :type="resultStatusTagType(displayStatus(unit))"
              >
                {{ resultStatusLabel(displayStatus(unit)) }}
              </el-tag>
              <span>{{ unitLabel(unit) }}</span>
            </span>
          </template>
        </el-tab-pane>
      </el-tabs>

      <div
        v-if="activeUnit"
        class="unit-body"
      >
        <!-- 結果未知：不是失敗也不是成功，畫面必須明說並給出可查的去處 -->
        <el-alert
          v-if="activeUnit.resultUnknown"
          class="unit-banner"
          type="warning"
          show-icon
          :closable="false"
          :title="t('dbConsole.results.unknownTitle')"
        >
          <p class="banner-line">
            {{ t('dbConsole.results.unknownHint') }}
          </p>
          <p class="banner-line">
            <span class="event-id">{{ activeUnit.eventId }}</span>
            <el-button
              link
              type="primary"
              size="small"
              @click="copyEventId(activeUnit.eventId)"
            >
              {{ t('dbConsole.results.copyEventId') }}
            </el-button>
            <router-link
              v-if="auditLinkTo"
              :to="auditLinkTo"
              class="audit-link"
            >
              {{ t('dbConsole.results.viewAudit') }}
            </router-link>
          </p>
        </el-alert>

        <el-alert
          v-else-if="isAlertStatus(activeUnit.status)"
          class="unit-banner"
          type="warning"
          show-icon
          :closable="false"
          :title="t(`dbConsole.results.alert.${activeUnit.status}`)"
          :description="resultReasonLabel(activeUnit.reason)"
        />

        <!-- 截斷是回傳上限，不是目標端只算了這些列；指引要能直接照做 -->
        <el-alert
          v-if="activeUnit.truncated"
          class="unit-banner"
          type="info"
          show-icon
          :closable="false"
          :title="t('dbConsole.results.truncatedTitle', { rows: rowLimit })"
          :description="truncationHint"
        />

        <div class="unit-status">
          <span>{{ t('dbConsole.results.statusLabel') }}
            <el-tag
              size="small"
              :type="resultStatusTagType(displayStatus(activeUnit))"
            >{{ resultStatusLabel(displayStatus(activeUnit)) }}</el-tag>
          </span>
          <span v-if="activeUnit.reason">
            {{ t('dbConsole.results.reasonLabel') }} {{ resultReasonLabel(activeUnit.reason) }}
          </span>
          <!-- 驅動程式對查詢類語句回 -1 表示「這個數字不適用」，那不是一個列數 -->
          <span v-if="activeUnit.rowsAffected > 0">
            {{ t('dbConsole.results.rowsAffected', { n: activeUnit.rowsAffected }) }}
          </span>
          <span v-if="activeSet">
            {{ t('dbConsole.results.rowCount', { n: activeSet.row_count || 0 }) }}
          </span>
          <span v-if="activeUnit.durationMs">
            {{ t('dbConsole.results.duration', { ms: activeUnit.durationMs }) }}
          </span>
          <span class="event-id-inline">
            {{ activeUnit.eventId }}
            <el-button
              link
              type="primary"
              size="small"
              @click="copyEventId(activeUnit.eventId)"
            >
              {{ t('dbConsole.results.copyEventId') }}
            </el-button>
          </span>
        </div>

        <el-tabs
          v-if="activeUnit.sets.length > 1"
          :model-value="String(selection.setIndex)"
          class="set-tabs"
          @update:model-value="selectSet"
        >
          <el-tab-pane
            v-for="set in activeUnit.sets"
            :key="set.set_index"
            :name="String(set.set_index)"
            :label="t('dbConsole.results.setLabel', { n: set.set_index + 1 })"
          />
        </el-tabs>

        <!-- 沒有結果集時說的話必須跟著這一筆的下場走：語句沒跑成功、還在跑、
             或結果根本不知道，都不能叫使用者「確認查詢條件」 -->
        <EmptyState
          v-if="bodyState"
          :title="t(bodyState.title)"
          :hint="t(bodyState.hint)"
          :icon="TableIcon"
        />
        <template v-else-if="activeSet && activeSet.columns.length">
          <div class="table-wrap">
            <!-- 捲軸常駐：欄數多時橫向捲動是唯一看得到末欄的路，捲軸只在滑過時才現身
                 等於沒有入口——使用者會把「看不到後面幾欄」讀成資料沒回來 -->
            <el-table
              :data="pagedRows"
              stripe
              show-overflow-tooltip
              scrollbar-always-on
              size="small"
              height="100%"
            >
              <el-table-column
                v-for="(col, index) in activeSet.columns"
                :key="col.name + index"
                :label="col.name"
                :min-width="COLUMN_MIN_WIDTH"
              >
                <!-- 欄名自己接管呈現：表頭不吃 show-overflow-tooltip，預設會折行成
                     兩三列並把後面的欄一起擠高，長欄名仍然讀不到全文 -->
                <template #header>
                  <span
                    class="column-name"
                    :title="col.name"
                  >{{ col.name }}</span>
                </template>
                <template #default="{ row }">
                  <span
                    v-if="row.cells[index] === null"
                    class="cell-null"
                  >NULL</span>
                  <span v-else>{{ row.cells[index] }}</span>
                </template>
              </el-table-column>
            </el-table>
          </div>
          <div class="pagination">
            <el-pagination
              v-model:current-page="page"
              v-model:page-size="pageSize"
              :total="rows.length"
              :page-sizes="[20, 50, 100, 200]"
              layout="total, sizes, prev, pager, next, jumper"
            />
          </div>
        </template>
      </div>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { Table2 as TableIcon } from 'lucide-vue-next'
import EmptyState from '@/components/EmptyState.vue'
import { t } from '@/i18n'
import {
  resultStatusLabel,
  resultStatusTagType,
  resultReasonLabel,
  isAlertStatus,
} from '@/constants/db-console'

const props = defineProps({
  units: { type: Array, default: () => [] },
  // 目前檢視的 (event_id, set_index)：匯出鈕以此定址
  selection: { type: Object, default: () => ({ eventId: '', setIndex: 0 }) },
  // 伺服端下發的上限，用於截斷文案（不硬編數字）
  limits: { type: Object, default: () => ({}) },
  // 會話詳情的深連結：僅具稽核權限者看得到，其他人以事件識別轉交
  auditLinkTo: { type: [Object, String], default: null },
})

const emit = defineEmits(['update:selection'])

const page = ref(1)
const pageSize = ref(50)

// 每欄的下限寬度：欄數多時表格改走橫向捲動，寬度不再被欄數瓜分。
// 取值要容得下常見欄名與一段可判讀的值，又不讓十來欄就得捲上好幾屏
const COLUMN_MIN_WIDTH = 140

const activeUnit = computed(
  () => props.units.find((u) => u.eventId === props.selection.eventId) || null
)
const activeSet = computed(() => {
  const sets = activeUnit.value?.sets || []
  return sets.find((s) => s.set_index === props.selection.setIndex) || sets[0] || null
})
const rowLimit = computed(() => props.limits.rows_per_unit || 0)

// 每列包一層物件：el-table 的 row 必須是物件，且要能區分 null 與空字串
const rows = computed(() =>
  (activeSet.value?.rows || []).map((cells, index) => ({ index, cells }))
)
const pagedRows = computed(() => {
  const start = (page.value - 1) * pageSize.value
  return rows.value.slice(start, start + pageSize.value)
})

const truncationHint = computed(() =>
  t('dbConsole.results.truncatedHint') +
  (activeUnit.value?.reason === 'cell_truncated'
    ? ` ${t('dbConsole.results.cellTruncatedHint')}`
    : '')
)

// 沒回終態就斷線的單位不顯示 running：它已經不是「進行中」，而是「不知道」
const displayStatus = (unit) =>
  unit.resultUnknown ? 'effect_unknown' : unit.status

// 重連自報的佔位列沒有伺服端序號，0 不是它的序號
const unitLabel = (unit) =>
  unit.seq > 0
    ? t('dbConsole.results.unitLabel', { seq: unit.seq })
    : t('dbConsole.results.unitLabelPending')

// 沒有結果集可畫時要說哪一句：null＝有資料列，交給下面的表格
const bodyState = computed(() => {
  const unit = activeUnit.value
  if (!unit) return null
  if (activeSet.value?.columns.length) return null
  // 結果未知已由上方橫幅講完，這裡再補一句只是把同一件事說兩次
  if (unit.resultUnknown) return null
  if (unit.status === 'running') {
    return {
      title: 'dbConsole.results.runningTitle',
      hint: 'dbConsole.results.runningHint',
    }
  }
  if (unit.status === 'error') {
    return {
      title: 'dbConsole.results.failedTitle',
      hint: 'dbConsole.results.failedHint',
    }
  }
  // 「請確認查詢條件」只在語句真的跑完時才成立；阻斷、取消、逾時的下場
  // 已由狀態列與橫幅講完，這裡不再多說一句可能是假的話
  if (unit.status !== 'ok' && unit.status !== 'partial') return null
  return {
    title: 'dbConsole.results.noRowsTitle',
    hint: 'dbConsole.results.noRowsHint',
  }
})

function selectUnit(eventId) {
  emit('update:selection', { eventId, setIndex: 0 })
}

function selectSet(value) {
  emit('update:selection', {
    eventId: props.selection.eventId,
    setIndex: Number(value) || 0,
  })
}

async function copyEventId(eventId) {
  try {
    await navigator.clipboard.writeText(eventId)
    ElMessage.success(t('dbConsole.results.copied'))
  } catch {
    ElMessage.warning(t('dbConsole.results.copyFailed'))
  }
}

watch(
  () => [props.selection.eventId, props.selection.setIndex],
  () => {
    page.value = 1
  }
)
</script>

<style scoped>
.db-console-results {
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
  padding: var(--ot-space-sm);
  gap: var(--ot-space-xs);
  overflow: hidden;
}

.unit-tabs {
  flex: none;
}

.unit-label {
  display: inline-flex;
  align-items: center;
  gap: var(--ot-space-xs);
}

.unit-body {
  display: flex;
  flex-direction: column;
  flex: 1 1 auto;
  min-height: 0;
  gap: var(--ot-space-xs);
}

.unit-banner {
  flex: none;
}

.banner-line {
  margin: var(--ot-space-xs) 0 0;
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  flex-wrap: wrap;
}

.event-id,
.event-id-inline {
  font-family: var(--ot-font-mono);
  font-size: var(--ot-font-size-sm);
}

.event-id-inline {
  margin-left: auto;
  display: inline-flex;
  align-items: center;
  gap: var(--ot-space-xs);
}

.audit-link {
  color: var(--el-color-primary);
}

.unit-status {
  flex: none;
  display: flex;
  align-items: center;
  gap: var(--ot-space-md);
  flex-wrap: wrap;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.set-tabs {
  flex: none;
}

/* 橫向溢位交給表格自己的捲動區承接：外層再夾一層 overflow 會把捲軸連同末欄一起藏掉 */
.table-wrap {
  flex: 1 1 auto;
  min-height: 120px;
}

/* 表頭不折行：長欄名以省略號收尾，全文走 title */
.table-wrap :deep(.el-table__header-wrapper .cell) {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.column-name {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* 儲存格左右各 12px 的留白在欄數多時吃掉可讀寬度的兩成 */
.table-wrap :deep(.el-table .cell) {
  padding-left: var(--ot-space-sm);
  padding-right: var(--ot-space-sm);
}

.cell-null {
  color: var(--ot-text-disabled);
  font-style: italic;
}

.pagination {
  flex: none;
  display: flex;
  justify-content: flex-end;
  padding-top: var(--ot-space-xs);
}
</style>
