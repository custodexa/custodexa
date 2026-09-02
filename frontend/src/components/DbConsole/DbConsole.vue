<template>
  <div class="db-console">
    <DbConsoleStatusOverlay
      v-if="!socket.connected.value"
      :status="socket.status.value"
      :detail="socket.statusDetail.value"
      @reconnect="reconnect"
    />

    <div class="console-toolbar">
      <el-select
        :model-value="socket.currentDatabase.value || undefined"
        size="small"
        class="database-select"
        filterable
        :disabled="!socket.connected.value || switching"
        :placeholder="t('dbConsole.databasePlaceholder')"
        :empty-values="[null, undefined]"
        :class="{ 'is-restricted': !socket.databaseAllowed.value }"
        @change="onDatabaseChange"
      >
        <el-option
          v-for="db in socket.databases.value"
          :key="db.name"
          :label="db.name"
          :value="db.name"
          :disabled="db.connectable === false"
        />
      </el-select>

      <!-- 提示往上開且不可停留：往下開會落在執行鈕那一列上，滑鼠移過去就點不到 -->
      <el-tooltip
        :content="exportTooltip"
        placement="top"
        :enterable="false"
      >
        <span class="export-wrap">
          <el-button
            size="small"
            :icon="Download"
            :disabled="exportDisabledReason !== ''"
            :loading="exporting"
            @click="exportCsv"
          >
            {{ t('dbConsole.export') }}
          </el-button>
        </span>
      </el-tooltip>

      <span
        v-if="socket.txState.value === 'active'"
        class="tx-badge"
      >{{ t('dbConsole.tx.active') }}</span>
    </div>
    <!-- 目標受限：會話還在，但當前庫落在允許清單外，送出一律被拒 -->
    <el-alert
      v-if="!socket.databaseAllowed.value"
      class="console-banner"
      type="error"
      show-icon
      :closable="false"
      :title="t(`dbConsole.restricted.${socket.restrictedCode.value || 'database_not_allowed'}`)"
      :description="t('dbConsole.restrictedHint')"
    />

    <!-- 交易失敗態常駐：不代發 ROLLBACK，指引是文字，動作由使用者自己下 -->
    <el-alert
      v-if="socket.txState.value === 'failed'"
      class="console-banner"
      type="warning"
      show-icon
      :closable="false"
      :title="t(dialectTxFailedKey)"
      :description="t('dbConsole.tx.failedHint')"
    />

    <el-alert
      v-if="exportError"
      class="console-banner"
      type="error"
      show-icon
      :title="exportError"
      @close="exportError = ''"
    />

    <DbConsoleBoundaryPanel />

    <div class="console-body">
      <DbConsoleTree
        class="pane-tree"
        :databases="socket.databases.value"
        :current-database="socket.currentDatabase.value"
        :loading="treeLoading"
        :switching="switching"
        :truncated="treeTruncated"
        :node-limit="socket.limits.value.tree_nodes_per_level || 2000"
        :allowed-databases="allowedDatabases"
        :fetch-children="fetchChildren"
        @switch="onDatabaseChange"
        @refresh="refreshTree"
      />
      <div class="pane-right">
        <DbConsoleEditor
          class="pane-editor"
          :model-value="sql"
          :dialect="socket.dialect.value"
          :busy="socket.busy.value"
          :disabled="!socket.connected.value || !socket.databaseAllowed.value"
          :error="socket.lastError.value"
          @update:model-value="onSqlChange"
          @execute="onExecute"
          @cancel="socket.cancel"
        />
        <!-- 重連清空結果是既定行為；不說一聲，使用者會把「結果沒了」讀成資料遺失 -->
        <el-alert
          v-if="reconnectNotice"
          class="session-notice"
          type="info"
          show-icon
          :title="t('dbConsole.reconnectedTitle')"
          :description="t('dbConsole.reconnectedHint')"
          @close="reconnectNotice = false"
        />
        <DbConsoleResults
          class="pane-results"
          :units="socket.units.value"
          :selection="selection"
          :limits="socket.limits.value"
          :audit-link-to="auditLinkTo"
          @update:selection="selection = $event"
        />
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch, onMounted, onBeforeUnmount } from 'vue'
import { Download } from 'lucide-vue-next'
import DbConsoleTree from './DbConsoleTree.vue'
import DbConsoleEditor from './DbConsoleEditor.vue'
import DbConsoleResults from './DbConsoleResults.vue'
import DbConsoleStatusOverlay from './DbConsoleStatusOverlay.vue'
import DbConsoleBoundaryPanel from './DbConsoleBoundaryPanel.vue'
import { useDbConsoleSocket } from '@/composables/useDbConsoleSocket'
import { useResultExport } from './use-result-export'
import { confirmResend, confirmSwitchDatabase } from './confirmations'
import { isTxUnsettled } from '@/constants/db-console'
import { useRoles } from '@/composables/useRoles'
import { t } from '@/i18n'

const props = defineProps({
  assetId: { type: [Number, String], required: true },
  accountId: { type: [Number, String], default: null },
  assetName: { type: String, default: '' },
  // 資產的允許清單：只用於分辨兩種空態的文案
  allowedDatabases: { type: Array, default: () => [] },
  // 重連時由分頁狀態交還：上一場會話與未收束的單位
  previousSessionId: { type: [Number, String], default: null },
  pendingEventId: { type: String, default: '' },
  pendingSql: { type: String, default: '' },
  // 編輯器文字存在分頁狀態上，重建面板時交還
  initialSql: { type: String, default: '' },
})

const emit = defineEmits([
  'status-change',
  'session-id',
  'sql-change',
  'pending-change',
  'unsettled-change',
])

const { isPrivileged } = useRoles()

const socket = useDbConsoleSocket({
  assetId: props.assetId,
  accountId: props.accountId,
  previousSessionId: props.previousSessionId,
  pendingEventId: props.pendingEventId,
  pendingSql: props.pendingSql,
})

const sql = ref(props.initialSql)
const selection = ref({ eventId: props.pendingEventId || '', setIndex: 0 })
const switching = ref(false)
const treeLoading = ref(false)
const treeTruncated = ref(false)
// 重連提示只在重連真的成功後出現：連不上時畫面已由狀態覆蓋層說明
const reconnecting = ref(false)
const reconnectNotice = ref(false)

const activeUnit = computed(
  () => socket.units.value.find((u) => u.eventId === selection.value.eventId) || null
)

const {
  exporting,
  exportError,
  disabledReason: exportDisabledReason,
  tooltip: exportTooltip,
  run: exportCsv,
  refreshCapability,
} = useResultExport({
  activeUnit,
  setIndex: computed(() => selection.value.setIndex),
  socket,
  assetId: () => props.assetId,
  assetName: () => props.assetName,
})

// 交易失敗的文案逐方言不同：PostgreSQL 是「交易處於失敗狀態」，
// MSSQL 是「交易不可提交」——兩邊的目標端說法不同，不合併成一句
const dialectTxFailedKey = computed(() =>
  socket.dialect.value === 'mssql' ? 'dbConsole.tx.failedMssql' : 'dbConsole.tx.failed'
)

// 會話詳情只對具稽核權限者開放；其他人以事件識別轉交，不給一個點了會被擋的連結
const auditLinkTo = computed(() => {
  if (!isPrivileged.value || !socket.sessionId.value || !activeUnit.value) return null
  return {
    name: 'SessionDetail',
    params: { id: String(socket.sessionId.value) },
    hash: `#cmd-${activeUnit.value.eventId}`,
  }
})

const unsettled = computed(
  () =>
    socket.units.value.some((u) => u.status === 'running' || u.resultUnknown) ||
    isTxUnsettled(socket.txState.value)
)

// 新會話已就緒才明示：重連是新的一場會話，先前結果已隨舊會話清空
watch(socket.connected, (value) => {
  if (!value || !reconnecting.value) return
  reconnecting.value = false
  reconnectNotice.value = true
})
watch(socket.tabStatus, (value) => emit('status-change', value), { immediate: true })
watch(socket.sessionId, (value) => value && emit('session-id', value))
watch(unsettled, (value) => emit('unsettled-change', value), { immediate: true })
// 進行中的單位在面板被拆掉的那一刻就變成「結果未知」，而拆掉時已經來不及往上報。
// 因此進行中就先把識別交還分頁狀態，收到終態再清掉——重新連線是使用者在語句卡住時
// 最自然的動作，新面板必須帶著它去問那一筆的下場
const unsettledEventId = computed(
  () => socket.pendingEventId.value || socket.activeEventId.value
)
watch(
  () => [unsettledEventId.value, socket.pendingSql.value],
  ([eventId, pendingSql]) => emit('pending-change', { eventId, sql: pendingSql })
)
// 新單位出現即切到它：使用者送出後要看到的是這一筆的結果
watch(
  () => socket.units.value.length,
  () => {
    const last = socket.units.value.at(-1)
    if (last) selection.value = { eventId: last.eventId, setIndex: 0 }
  }
)

function onSqlChange(value) {
  sql.value = value
  emit('sql-change', value)
}

async function onExecute(text) {
  // 上一筆相同原文的結果未知：重送等於讓同一個效果可能發生兩次
  const resending = socket.pendingEventId.value && text === socket.pendingSql.value
  if (resending && !(await confirmResend())) return
  socket.sendQuery(text)
}

async function onDatabaseChange(database) {
  if (!database || database === socket.currentDatabase.value) return
  // PostgreSQL 的連線綁在庫上：換庫等於換一條連線，未提交的交易會隨舊連線消失
  if (socket.dialect.value === 'postgres') {
    const ok = await confirmSwitchDatabase(database, isTxUnsettled(socket.txState.value))
    if (!ok) return
  }
  switching.value = true
  socket.switchDatabase(database)
  // 切庫的結果以 notice 回報；此處只是不讓使用者在等待期間連按
  setTimeout(() => {
    switching.value = false
  }, 300)
}

async function fetchChildren(request) {
  const res = await socket.requestTree(request)
  if (res?.truncated) treeTruncated.value = true
  return res
}

async function refreshTree() {
  treeLoading.value = true
  treeTruncated.value = false
  try {
    await socket.requestTree({ level: 'databases' })
  } catch {
    // 成因已由錯誤面板呈現
  } finally {
    treeLoading.value = false
  }
}

function reconnect() {
  exportError.value = ''
  reconnectNotice.value = false
  reconnecting.value = true
  socket.reconnect()
  // 未收束的單位在 reconnect 內才被收成佔位列，選取要在那之後才指得到它
  selection.value = { eventId: socket.pendingEventId.value || '', setIndex: 0 }
}

onMounted(() => {
  document.addEventListener('visibilitychange', refreshCapability)
  socket.connect()
})

onBeforeUnmount(() => {
  document.removeEventListener('visibilitychange', refreshCapability)
  socket.dispose()
})

defineExpose({ reconnect, unsettled })
</script>

<style scoped>
.db-console {
  position: relative;
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
  background: var(--el-bg-color);
}

.console-toolbar {
  flex: none;
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  padding: var(--ot-space-sm);
  border-bottom: 1px solid var(--el-border-color-lighter);
}

.database-select {
  width: 220px;
}

.database-select.is-restricted :deep(.el-select__wrapper) {
  box-shadow: 0 0 0 1px var(--el-color-danger) inset;
}

.export-wrap {
  display: inline-flex;
}

.tx-badge {
  margin-left: auto;
  font-size: var(--ot-font-size-sm);
  color: var(--el-color-warning);
}

.console-banner,
.session-notice {
  flex: none;
}

.console-body {
  flex: 1 1 auto;
  min-height: 0;
  display: flex;
}

.pane-tree {
  flex: none;
  width: 260px;
}

.pane-right {
  flex: 1 1 auto;
  min-width: 0;
  display: flex;
  flex-direction: column;
}

.pane-editor {
  flex: 0 0 38%;
  min-height: 0;
}

.pane-results {
  flex: 1 1 auto;
  min-height: 0;
  border-top: 1px solid var(--el-border-color-lighter);
}
</style>
