<template>
  <div class="change-secret-batches">
    <PageHeader
      :title="$t('menu.changeSecretBatches')"
      :description="$t('changeSecretBatches.description')"
    >
      <template #actions>
        <el-button
          :loading="targetsLoading"
          @click="reload"
        >
          {{ $t('common.refresh') }}
        </el-button>
        <el-button
          type="primary"
          :disabled="!selectedCount"
          data-test="open-batch"
          @click="openBatch"
        >
          {{ $t('changeSecretBatches.batchAction', { count: selectedCount }) }}
        </el-button>
      </template>
    </PageHeader>

    <div class="toolbar">
      <el-select
        v-model="username"
        filterable
        clearable
        class="username-select"
        data-test="username-select"
        :placeholder="$t('changeSecretBatches.usernamePlaceholder')"
        @change="selectUsername"
      >
        <el-option
          v-for="item in usernames"
          :key="item.username"
          :value="item.username"
          :label="$t('changeSecretBatches.usernameOption', {
            username: item.username,
            count: item.asset_count,
          })"
        />
      </el-select>
      <span
        v-if="username"
        class="muted"
        data-test="targets-summary"
      >
        {{ $t('changeSecretBatches.targetsSummary', {
          total: targets.length,
          eligible: eligibleTargets.length,
        }) }}
      </span>
    </div>

    <EmptyState
      v-if="!username"
      :title="$t('changeSecretBatches.pickUsernameTitle')"
      :hint="$t('changeSecretBatches.pickUsernameHint')"
    />
    <EmptyState
      v-else-if="!targets.length && !targetsLoading"
      :title="$t('changeSecretBatches.emptyTargetsTitle')"
      :hint="$t('changeSecretBatches.emptyTargetsHint')"
    />
    <div
      v-else
      v-loading="targetsLoading"
      class="board"
      data-test="target-board"
    >
      <div
        v-for="column in columns"
        :key="column.bucket"
        class="board-column"
        :data-test="`bucket-column-${column.bucket}`"
      >
        <div class="column-head">
          <el-tag
            size="small"
            effect="plain"
            :type="bucketTagType(column.bucket)"
          >
            {{ bucketLabel(column.bucket) }}
          </el-tag>
          <span
            class="column-count"
            :data-test="`bucket-count-${column.bucket}`"
          >{{ column.items.length }}</span>
          <span class="spacer" />
          <el-button
            link
            size="small"
            :disabled="!eligibleIn(column).length"
            :data-test="`bucket-select-${column.bucket}`"
            @click="toggleColumn(column)"
          >
            {{ isColumnSelected(column)
              ? $t('changeSecretBatches.clearAll')
              : $t('changeSecretBatches.selectAll') }}
          </el-button>
        </div>

        <div class="column-body">
          <div
            v-for="row in column.items"
            :key="row.account_id"
            class="target-card"
            :data-test="`target-card-${row.account_id}`"
          >
            <div class="card-head">
              <el-checkbox
                :model-value="isSelected(row)"
                :disabled="!eligible(row)"
                :data-test="`target-check-${row.account_id}`"
                @change="toggleTarget(row)"
              />
              <span class="asset-name">{{ row.asset_name }}</span>
              <span
                v-if="row.remaining_days_a !== null && row.remaining_days_a !== undefined"
                class="remaining"
                :class="{ overdue: row.remaining_days_a < 0, soon: row.remaining_days_a >= 0 }"
              >{{ remainingText(row.remaining_days_a) }}</span>
            </div>

            <div class="card-account">
              <span class="mono">{{ row.username }}</span>
              <el-tag
                v-if="row.privileged"
                size="small"
                type="danger"
                effect="plain"
              >
                {{ $t('rotationEvidence.tag.privileged') }}
              </el-tag>
              <el-tag
                v-if="row.shared_credential"
                size="small"
                type="warning"
                effect="plain"
              >
                {{ $t('rotationEvidence.tag.shared') }}
              </el-tag>
              <el-tag
                v-if="row.multi_plan"
                size="small"
                type="info"
                effect="plain"
              >
                {{ $t('rotationEvidence.tag.multiPlan') }}
              </el-tag>
            </div>

            <div class="card-foot">
              <span class="muted">{{ channelText(row.rotation_channel) }}</span>
              <span class="spacer" />
              <el-button
                v-if="eligible(row)"
                link
                size="small"
                type="warning"
                :data-test="`target-rotate-${row.account_id}`"
                @click="openSingle(row)"
              >
                {{ $t('changeSecretBatches.rotateNow') }}
              </el-button>
              <span
                v-else
                class="muted reason"
                :data-test="`target-reason-${row.account_id}`"
              >{{ reasonText(row.ineligible_reason) }}</span>
            </div>
          </div>

          <div
            v-if="!column.items.length"
            class="muted column-empty"
          >
            {{ $t('changeSecretBatches.columnEmpty') }}
          </div>
        </div>
      </div>
    </div>

    <div
      v-if="activeBatch"
      class="result-panel"
      data-test="batch-result"
    >
      <div class="panel-head">
        <h3>{{ $t('changeSecretBatches.resultTitle', { id: activeBatch.id }) }}</h3>
        <el-tag
          size="small"
          effect="plain"
          data-test="batch-mode"
        >
          {{ passwordModeText(activeBatch.password_mode) }}
        </el-tag>
        <el-tag
          size="small"
          effect="plain"
          :type="activeBatch.status === 'completed' ? 'success' : 'warning'"
          data-test="batch-status"
        >
          {{ batchStatusText(activeBatch.status) }}
        </el-tag>
      </div>
      <div
        class="muted"
        data-test="batch-counts"
      >
        {{ $t('changeSecretBatches.counts', {
          total: activeBatch.target_count,
          success: activeBatch.success_count,
          failed: activeBatch.failed_count,
          unverified: activeBatch.unverified_count,
          skipped: activeBatch.skipped_count,
        }) }}
      </div>
      <el-alert
        v-if="pollExhausted"
        type="info"
        :closable="false"
        show-icon
        data-test="poll-exhausted"
        :title="$t('changeSecretBatches.pollExhausted')"
      />
      <el-table
        :data="activeRecords"
        stripe
        row-key="id"
      >
        <el-table-column
          :label="$t('changeSecretBatches.colTarget')"
          min-width="200"
        >
          <template #default="{ row }">
            {{ assetName(row.asset_id) }} / {{ row.account_username }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('changeSecretPlans.colChannel')"
          min-width="140"
        >
          <template #default="{ row }">
            {{ recordChannelText(row) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('changeSecretBatches.colResult')"
          width="140"
        >
          <template #default="{ row }">
            <el-tag
              effect="plain"
              :type="recordTagType(row.status)"
              :data-test="`record-status-${row.id}`"
            >
              {{ recordStatusText(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('changeSecretBatches.colReason')"
          min-width="220"
        >
          <template #default="{ row }">
            {{ reasonText(row.error) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('changeSecretBatches.colExecutedAt')"
          width="180"
        >
          <template #default="{ row }">
            {{ formatDateTime(row.executed_at) }}
          </template>
        </el-table-column>
        <template #empty>
          <span class="muted">{{ $t('changeSecretBatches.recordsEmpty') }}</span>
        </template>
      </el-table>
    </div>

    <div class="recent-panel">
      <div class="panel-head">
        <h3>{{ $t('changeSecretBatches.recentTitle') }}</h3>
      </div>
      <el-table
        v-loading="batchesLoading"
        :data="batches"
        stripe
        row-key="id"
      >
        <el-table-column
          prop="id"
          :label="$t('changeSecretBatches.colBatch')"
          width="90"
        />
        <el-table-column
          prop="username"
          :label="$t('changeSecretPlans.colAccount')"
          min-width="130"
        />
        <el-table-column
          :label="$t('changeSecretBatches.colMode')"
          min-width="130"
        >
          <template #default="{ row }">
            {{ passwordModeText(row.password_mode) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('changeSecretBatches.colCounts')"
          min-width="240"
        >
          <template #default="{ row }">
            {{ $t('changeSecretBatches.counts', {
              total: row.target_count,
              success: row.success_count,
              failed: row.failed_count,
              unverified: row.unverified_count,
              skipped: row.skipped_count,
            }) }}
          </template>
        </el-table-column>
        <el-table-column
          prop="requested_by_name"
          :label="$t('changeSecretBatches.colRequestedBy')"
          min-width="120"
        />
        <el-table-column
          :label="$t('common.createdAt')"
          width="180"
        >
          <template #default="{ row }">
            {{ formatDateTime(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.actions')"
          width="100"
          fixed="right"
        >
          <template #default="{ row }">
            <el-button
              link
              size="small"
              type="primary"
              :data-test="`batch-view-${row.id}`"
              @click="openHistory(row)"
            >
              {{ $t('changeSecretBatches.view') }}
            </el-button>
          </template>
        </el-table-column>
        <template #empty>
          <span class="muted">{{ $t('changeSecretBatches.recentEmpty') }}</span>
        </template>
      </el-table>
    </div>

    <el-dialog
      v-model="dialogVisible"
      width="560px"
      :title="$t('changeSecretBatches.dialogTitle')"
    >
      <div
        class="dialog-targets"
        data-test="dialog-targets"
      >
        {{ $t('changeSecretBatches.dialogTargets', { count: selectedCount }) }}
      </div>

      <div class="policy-row">
        <span class="policy-label">{{ $t('changeSecretBatches.passwordMode') }}</span>
        <el-radio-group
          v-model="form.password_mode"
          data-test="password-mode"
        >
          <el-radio value="per_target">
            {{ $t('changeSecretBatches.modePerTarget') }}
          </el-radio>
          <el-radio value="shared">
            {{ $t('changeSecretBatches.modeShared') }}
          </el-radio>
        </el-radio-group>
      </div>

      <el-alert
        v-if="form.password_mode === 'shared'"
        type="warning"
        :closable="false"
        show-icon
        data-test="shared-risk"
        :title="$t('changeSecretBatches.sharedRiskTitle')"
        :description="$t('changeSecretBatches.sharedRisk')"
      />

      <div class="policy-row">
        <span class="policy-label">{{ $t('changeSecretPlans.passwordLength') }}</span>
        <el-input-number
          v-model="form.password_length"
          :min="12"
          :max="64"
        />
      </div>
      <div class="policy-row">
        <el-checkbox v-model="form.password_include_symbol">
          {{ $t('changeSecretPlans.passwordIncludeSymbol') }}
        </el-checkbox>
        <el-checkbox v-model="form.password_exclude_ambiguous">
          {{ $t('changeSecretPlans.passwordExcludeAmbiguous') }}
        </el-checkbox>
      </div>
      <div class="muted">
        {{ $t('changeSecretPlans.passwordLengthHint') }}
      </div>

      <template #footer>
        <el-button @click="dialogVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="submitting"
          :disabled="!selectedCount"
          data-test="submit-batch"
          @click="submit"
        >
          {{ $t('changeSecretBatches.submit') }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { ElMessage } from 'element-plus'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import { formatDateTime } from '@/utils/format'
import { t, te } from '@/i18n'
import { ROTATION_BUCKETS, BUCKET_TAG_TYPE } from '@/constants/rotationEvidence'
import {
  getChangeSecretBatchUsernames,
  getChangeSecretBatchTargets,
  createChangeSecretBatch,
  getChangeSecretBatches,
  getChangeSecretBatch,
} from '@/api/changeSecretBatches'

// 以帳號名為軸的處置看板：選帳號名 → 看見持有它的全部資產依狀態分欄 →
// 勾選目標整批改密。狀態桶與標記取自輪替證據的同一份資料集，
// 兩頁看到的分類逐字相同（一邊是稽核視角，一邊是處置入口）。

// 看板的欄序是處置優先序（先看逾期），與狀態桶的判定順序不同；
// 值域仍以狀態桶常數為準：不在下列順序內的桶接在後面，
// 未知的桶自成一欄——卡片總數恆等於目標數，不會有目標被靜默丟掉
const BOARD_BUCKET_ORDER = [
  'overdue',
  'due_soon',
  'no_record',
  'no_policy',
  'compliant',
  'unverified',
]
const boardBuckets = [
  ...BOARD_BUCKET_ORDER.filter((b) => ROTATION_BUCKETS.includes(b)),
  ...ROTATION_BUCKETS.filter((b) => !BOARD_BUCKET_ORDER.includes(b)),
]

// 送出後每隔數秒查一次批次，直到完成；上限存在是因為執行可能比人願意等的時間長，
// 逾時只停止輪詢並提示可稍後回看，批次本身照跑
const POLL_INTERVAL_MS = 2000
const POLL_MAX_TICKS = 150

const usernames = ref([])
const username = ref('')
const targets = ref([])
const targetsLoading = ref(false)
const selected = ref([])

const batches = ref([])
const batchesLoading = ref(false)

const activeBatch = ref(null)
const activeRecords = ref([])
const pollExhausted = ref(false)
// polling 是「還排著下一次查詢」的對外狀態；計時器本身不進響應式
const polling = ref(false)
let pollTimer = null

const dialogVisible = ref(false)
const submitting = ref(false)
const form = ref(emptyForm())

// 密碼策略的出廠預設與計劃相同（16、含符號、排除易混淆）；
// 密碼模式每次開對話框都回到「每台各自隨機」——整批同一組是要人明確選的那一個
function emptyForm() {
  return {
    password_mode: 'per_target',
    password_length: 16,
    password_include_symbol: true,
    password_exclude_ambiguous: true,
  }
}

const eligible = (row) => !row.ineligible_reason
const eligibleTargets = computed(() => targets.value.filter(eligible))
const selectedCount = computed(() => selected.value.length)

const columns = computed(() => {
  const groups = new Map(boardBuckets.map((bucket) => [bucket, []]))
  targets.value.forEach((row) => {
    const bucket = row.bucket || ''
    if (!groups.has(bucket)) groups.set(bucket, [])
    groups.get(bucket).push(row)
  })
  return [...groups.entries()].map(([bucket, items]) => ({ bucket, items }))
})

const bucketLabel = (bucket) =>
  ROTATION_BUCKETS.includes(bucket) ? t(`rotationEvidence.bucket.${bucket}`) : bucket || ''

const bucketTagType = (bucket) => BUCKET_TAG_TYPE[bucket] || 'info'

const remainingText = (days) =>
  days < 0
    ? t('rotationEvidence.overdueDays', { days: Math.abs(days) })
    : t('rotationEvidence.remainingDays', { days })

// 通道文字取共用的枚舉譯文；none 與未知值回空字串，由版面決定佔位
const channelText = (channel) =>
  channel && te(`enum.rotationChannel.${channel}`) && channel !== 'none'
    ? t(`enum.rotationChannel.${channel}`)
    : ''

// 不可改密原因與改密結果原因走同一組機器碼對照表，不另立第二份譯文；
// 查無對應鍵原樣顯示，不吞成空白
const reasonText = (code) => {
  if (!code) return ''
  const key = `changeSecretPlans.reason.${code}`
  return te(key) ? t(key) : code
}

const recordStatusText = (status) =>
  te(`changeSecretPlans.recordStatus.${status}`)
    ? t(`changeSecretPlans.recordStatus.${status}`)
    : status || ''

const recordTagType = (status) =>
  ({ success: 'success', failed: 'danger', unverified: 'warning', skipped: 'info' })[status] ||
  'info'

const passwordModeText = (mode) =>
  mode === 'shared'
    ? t('changeSecretBatches.modeShared')
    : t('changeSecretBatches.modePerTarget')

const batchStatusText = (status) =>
  status === 'completed'
    ? t('changeSecretBatches.statusCompleted')
    : t('changeSecretBatches.statusRunning')

// 記錄只帶資產識別；名稱與通道由目前的目標清單查表，查無對照時退回識別
const assetName = (assetId) => {
  const row = targets.value.find((item) => item.asset_id === assetId)
  return row ? row.asset_name : t('changeSecretBatches.assetFallback', { id: assetId })
}

const recordChannelText = (record) => {
  const row = targets.value.find((item) => item.account_id === record.account_id)
  return row ? channelText(row.rotation_channel) : ''
}

const isSelected = (row) => selected.value.includes(row.account_id)

const eligibleIn = (column) => column.items.filter(eligible)

const isColumnSelected = (column) => {
  const ids = eligibleIn(column)
  return ids.length > 0 && ids.every(isSelected)
}

function toggleTarget(row) {
  if (!eligible(row)) return
  selected.value = isSelected(row)
    ? selected.value.filter((id) => id !== row.account_id)
    : [...selected.value, row.account_id]
}

// 桶內全選只選可改密者：把停用的卡片也選進去，只會在送出時被整筆拒絕
function toggleColumn(column) {
  const ids = eligibleIn(column).map((row) => row.account_id)
  if (!ids.length) return
  selected.value = isColumnSelected(column)
    ? selected.value.filter((id) => !ids.includes(id))
    : [...new Set([...selected.value, ...ids])]
}

async function loadUsernames() {
  try {
    const res = await getChangeSecretBatchUsernames()
    usernames.value = res.data || []
  } catch (err) {
    console.error('[BatchRotation] 載入帳號名清單失敗:', err)
  }
}

async function loadTargets() {
  if (!username.value) {
    targets.value = []
    return
  }
  targetsLoading.value = true
  try {
    const res = await getChangeSecretBatchTargets(username.value)
    targets.value = res.data || []
    // 清單換過之後，已勾選的目標可能不再存在或不再可改密
    const keep = new Set(eligibleTargets.value.map((row) => row.account_id))
    selected.value = selected.value.filter((id) => keep.has(id))
  } catch (err) {
    console.error('[BatchRotation] 載入目標清單失敗:', err)
    targets.value = []
  } finally {
    targetsLoading.value = false
  }
}

async function loadBatches() {
  batchesLoading.value = true
  try {
    const res = await getChangeSecretBatches()
    batches.value = res.data || []
  } catch (err) {
    console.error('[BatchRotation] 載入最近批次失敗:', err)
  } finally {
    batchesLoading.value = false
  }
}

async function selectUsername(name) {
  username.value = name || ''
  selected.value = []
  await loadTargets()
}

async function reload() {
  await Promise.all([loadUsernames(), loadTargets(), loadBatches()])
}

function stopPolling() {
  if (pollTimer) {
    clearTimeout(pollTimer)
    pollTimer = null
  }
  polling.value = false
}

// 單次查詢＋自我排程：送出後先立刻查一次（批次可能已經跑完），
// 仍在執行才排下一次
async function pollBatch(id, tick = 0) {
  let status = ''
  try {
    const res = await getChangeSecretBatch(id)
    activeBatch.value = res.data?.batch || null
    activeRecords.value = res.data?.records || []
    status = activeBatch.value?.status || ''
  } catch (err) {
    console.error('[BatchRotation] 查詢批次失敗:', err)
    stopPolling()
    return
  }
  if (status === 'completed') {
    stopPolling()
    loadBatches()
    return
  }
  if (tick + 1 >= POLL_MAX_TICKS) {
    stopPolling()
    pollExhausted.value = true
    loadBatches()
    return
  }
  stopPolling()
  polling.value = true
  pollTimer = setTimeout(() => pollBatch(id, tick + 1), POLL_INTERVAL_MS)
}

function openBatch() {
  if (!selectedCount.value) return
  form.value = emptyForm()
  dialogVisible.value = true
}

// 卡片上的「立即改密」＝只對這一台，等同把選取換成它自己
function openSingle(row) {
  if (!eligible(row)) return
  selected.value = [row.account_id]
  form.value = emptyForm()
  dialogVisible.value = true
}

async function openHistory(row) {
  stopPolling()
  pollExhausted.value = false
  await pollBatch(row.id, 0)
}

// 一律明列已勾選的帳號識別，不用「全部符合者」：
// 管理員看到的清單與送出的集合必須是同一份，清單載入之後才出現的帳號不該被默默納入
async function submit() {
  if (!selectedCount.value) return
  submitting.value = true
  try {
    const res = await createChangeSecretBatch({
      username: username.value,
      account_ids: [...selected.value],
      all: false,
      password_mode: form.value.password_mode,
      password_length: form.value.password_length,
      password_include_symbol: form.value.password_include_symbol,
      password_exclude_ambiguous: form.value.password_exclude_ambiguous,
    })
    dialogVisible.value = false
    ElMessage.success(t('changeSecretBatches.accepted'))
    selected.value = []
    pollExhausted.value = false
    activeRecords.value = []
    activeBatch.value = res?.data || null
    loadBatches()
    if (activeBatch.value?.id) {
      stopPolling()
      await pollBatch(activeBatch.value.id, 0)
    }
  } catch (err) {
    console.error('[BatchRotation] 建立批次失敗:', err)
  } finally {
    submitting.value = false
  }
}

onMounted(() => {
  loadUsernames()
  loadBatches()
})

// 離開頁面即停止輪詢：留著的計時器會在元件卸載後繼續打 API
onUnmounted(stopPolling)
</script>

<style scoped>
.toolbar {
  display: flex;
  align-items: center;
  gap: var(--ot-space-md);
  margin-bottom: var(--ot-space-md);
}

.username-select {
  width: 260px;
}

.muted {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}

.board {
  display: flex;
  gap: var(--ot-space-md);
  align-items: flex-start;
  overflow-x: auto;
  padding-bottom: var(--ot-space-sm);
}

.board-column {
  flex: 1 1 0;
  min-width: 200px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.column-head {
  display: flex;
  align-items: center;
  gap: 8px;
  padding-bottom: 6px;
  border-bottom: 1px solid var(--ot-border-subtle);
}

.column-count {
  font-size: 13px;
  color: var(--el-text-color-regular);
}

.spacer {
  flex: 1;
}

.column-body {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.column-empty {
  padding: 8px 0;
}

.target-card {
  background: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  padding: 8px 10px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.card-head {
  display: flex;
  align-items: center;
  gap: 6px;
}

.asset-name {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-weight: 500;
}

.remaining {
  font-size: 12px;
  flex: none;
}

.remaining.overdue {
  color: var(--el-color-danger);
}

.remaining.soon {
  color: var(--el-text-color-regular);
}

.card-account {
  display: flex;
  align-items: center;
  gap: 4px;
  flex-wrap: wrap;
  font-size: 13px;
}

.card-foot {
  display: flex;
  align-items: center;
  gap: 6px;
}

.reason {
  text-align: right;
}

.result-panel,
.recent-panel {
  margin-top: var(--ot-space-lg);
  background: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  padding: var(--ot-space-md);
}

.panel-head {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}

.panel-head h3 {
  margin: 0;
  font-size: 15px;
}

.dialog-targets {
  margin-bottom: var(--ot-space-md);
}

.policy-row {
  display: flex;
  align-items: center;
  gap: var(--ot-space-md);
  margin: 8px 0;
}

.policy-label {
  font-size: 13px;
  color: var(--el-text-color-regular);
}

.mono {
  font-family: var(--ot-font-mono, monospace);
}
</style>
