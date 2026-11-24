<template>
  <!-- 未審閱告警：依類型分組（預設收合），每一列寫觸發者與對象；可全選這一天、勾整組或逐筆勾，
       以同一處置與理由一次送出（對話框在工作區，告警頁與跨日處置共用）。
       系統告警的列開明細、在明細逐筆處置；其餘告警在列上開單筆處置。
       每處置完就請父層重取該日明細——按鈕能不能按以伺服器的數字為準 -->
  <div
    class="dr-alerts"
    data-test="dr-alerts"
  >
    <!-- 來源已清除：已清除的告警不可能再處置，不擋簽核，但要說清楚 -->
    <div
      v-if="source === 'purged'"
      class="dr-alerts__notice"
      data-test="dr-alerts-purged"
    >
      <div class="dr-alerts__title">
        {{ $t('dailyReview.drawer.alerts.title') }}
      </div>
      <p>{{ $t('dailyReview.drawer.alerts.purged') }}</p>
    </div>

    <!-- 都處置完：摺疊成摘要 -->
    <div
      v-else-if="!alerts.length"
      class="dr-alerts__done"
      data-test="dr-alerts-done"
    >
      <CircleCheck
        :size="16"
        class="dr-alerts__ok"
        aria-hidden="true"
      />
      <div>
        <div class="dr-alerts__title">
          {{ total > 0
            ? $t('dailyReview.drawer.alerts.allDone', { total })
            : $t('dailyReview.drawer.alerts.none') }}
        </div>
        <div
          v-if="total > 0"
          class="dr-alerts__sub"
        >
          {{ $t('dailyReview.drawer.alerts.allDoneDetail', { benign: benign ?? 0, escalated: escalated ?? 0 }) }}
        </div>
      </div>
    </div>

    <template v-else>
      <div class="dr-alerts__head">
        <span class="dr-alerts__title">{{ $t('dailyReview.drawer.alerts.title') }}</span>
        <span
          class="dr-alerts__pending"
          data-test="dr-alerts-pending"
        >{{ pendingText }}</span>
      </div>
      <p
        v-if="canSign"
        class="dr-alerts__hint"
      >
        {{ $t('dailyReview.drawer.alerts.hint') }}
      </p>

      <!-- 全選列與批次列：同一個位置，捲動清單時黏在告警區頂端 -->
      <div
        v-if="canSign"
        :class="['dr-alerts__bar', { 'dr-alerts__bar--active': selectedCount > 0 }]"
        :style="STICKY_STYLE"
        data-test="dr-alerts-batch-bar"
      >
        <div class="dr-alerts__bar-line">
          <BatchCheckbox
            test-id="dr-alerts-select-all"
            :checked="allState.checked"
            :indeterminate="allState.indeterminate"
            :label="$t('dailyReview.drawer.alerts.selectAll', { n: alerts.length })"
            @change="toggleAll"
          />
          <span
            v-if="!selectedCount"
            class="dr-alerts__bar-text"
            data-test="dr-alerts-select-all-text"
          >{{ $t('dailyReview.drawer.alerts.selectAll', { n: alerts.length }) }}</span>
          <span
            v-else
            class="dr-alerts__bar-text"
            data-test="dr-alerts-selected"
          >{{ selectedText }}</span>
          <span
            v-if="!selectedCount"
            class="dr-alerts__bar-aside"
          >{{ $t('dailyReview.drawer.alerts.groupHint') }}</span>
        </div>
        <div
          v-if="selectedCount"
          class="dr-alerts__bar-line dr-alerts__bar-line--actions"
        >
          <span
            v-if="selectedCount > ALERT_BULK_LIMIT"
            class="dr-alerts__bar-limit"
            data-test="dr-alerts-limit-hint"
          >{{ $t('dailyReview.drawer.alerts.overLimit', { lim: ALERT_BULK_LIMIT, r: selectedCount - ALERT_BULK_LIMIT }) }}</span>
          <span class="dr-alerts__bar-spacer" />
          <el-button
            size="small"
            data-test="batch-clear"
            @click="clearSelection"
          >
            {{ $t('alerts.batch.clear') }}
          </el-button>
          <el-button
            v-preview-write
            type="primary"
            size="small"
            data-test="dr-alerts-batch-open"
            @click="openBatch"
          >
            {{ $t('dailyReview.drawer.alerts.batchOpen', { n: Math.min(selectedCount, ALERT_BULK_LIMIT) }) }}
          </el-button>
        </div>
      </div>

      <div class="dr-alerts__groups">
        <section
          v-for="group in groups"
          :key="group.key"
          :class="['dr-group', { 'dr-group--picked': groupState(group).checked || groupState(group).indeterminate }]"
          data-test="dr-alert-group"
          :data-key="group.key"
        >
          <header class="dr-group__head">
            <BatchCheckbox
              v-if="canSign"
              test-id="dr-alert-group-select"
              :checked="groupState(group).checked"
              :indeterminate="groupState(group).indeterminate"
              :label="$t('dailyReview.drawer.alerts.selectGroup', { type: group.name, n: group.rows.length })"
              @change="toggleGroup(group)"
            />
            <div class="dr-group__info">
              <div class="dr-group__line">
                <span
                  class="dr-group__name"
                  data-test="dr-alert-group-name"
                >{{ group.name }}</span>
                <el-tag
                  v-if="group.isRule"
                  size="small"
                  type="info"
                  data-test="dr-alert-group-rule-tag"
                >
                  {{ $t('dailyReview.drawer.alerts.commandTag') }}
                </el-tag>
                <el-tag
                  size="small"
                  effect="plain"
                  :type="SEV_TAG[group.severity] || 'info'"
                >
                  {{ severityLabel(group.severity) }}
                </el-tag>
                <span class="dr-group__count">{{ $t('dailyReview.drawer.alerts.groupCount', { n: group.rows.length }) }}</span>
              </div>
              <div
                class="dr-group__sub"
                data-test="dr-alert-group-sub"
              >
                <span
                  v-for="(user, i) in group.users"
                  :key="i"
                  :class="{ 'dr-group__self': user.self }"
                >{{ i ? ' · ' : '' }}{{ $t('dailyReview.drawer.alerts.userCount', { user: user.name, n: user.count }) }}</span>
                <span class="dr-group__range"> · {{ rangeText(group) }}</span>
              </div>
            </div>
            <el-button
              link
              type="primary"
              size="small"
              data-test="dr-alert-group-toggle"
              @click="toggleExpand(group.key)"
            >
              {{ expanded.has(group.key)
                ? $t('dailyReview.drawer.alerts.collapse')
                : $t('dailyReview.drawer.alerts.expand', { n: group.rows.length }) }}
              <ChevronUp
                v-if="expanded.has(group.key)"
                :size="14"
                aria-hidden="true"
              />
              <ChevronDown
                v-else
                :size="14"
                aria-hidden="true"
              />
            </el-button>
          </header>
          <ul
            v-if="expanded.has(group.key)"
            class="dr-alerts__list"
          >
            <li
              v-for="row in group.rows"
              :key="row.id"
              class="dr-alerts__row"
              :data-test="`dr-alert-${row.id}`"
            >
              <BatchCheckbox
                v-if="canSign"
                test-id="dr-alert-select"
                :data-id="row.id"
                :checked="isSelected(row)"
                :disabled="!isSelectable(row)"
                :label="$t('alerts.batch.selectRow', { label: labelFor(row) })"
                @change="(checked) => toggleRow(row, checked)"
              />
              <span class="dr-alerts__time">{{ timeInZone(row.triggered_at, timezone) }}</span>
              <span :class="['dr-alerts__sev', `dr-alerts__sev--${row.severity}`]">{{ severityLabel(row.severity) }}</span>
              <div class="dr-alerts__what">
                <div
                  class="dr-alerts__who"
                  data-test="dr-alert-who"
                >
                  {{ whoLine(row) }}
                </div>
                <div
                  v-if="secondLine(row)"
                  :class="['dr-alerts__detail', { 'dr-alerts__detail--mono': !isSystemAlert(row) && row.command }]"
                  data-test="dr-alert-detail"
                >
                  {{ secondLine(row) }}
                </div>
              </div>
              <el-button
                v-if="isSystemAlert(row)"
                link
                type="primary"
                size="small"
                data-test="dr-alert-view"
                @click="openDetail(group, row)"
              >
                {{ $t('dailyReview.drawer.alerts.view') }}
              </el-button>
              <el-button
                v-else-if="canSign"
                v-preview-write
                link
                type="primary"
                size="small"
                data-test="dr-alert-single"
                @click="openSingle(row)"
              >
                {{ $t('dailyReview.drawer.alerts.single') }}
              </el-button>
            </li>
          </ul>
        </section>
      </div>
    </template>

    <!-- 系統告警的明細：這一組內上一筆、下一筆，有權限時可逐筆處置 -->
    <SystemAlertDetailDrawer
      v-model="detailOpen"
      :alert-id="detailId"
      append-to-body
      :position="detailPosition"
      :reviewable="canSign"
      @prev="stepDetail(-1)"
      @next="stepDetail(1)"
      @reviewed="onDetailReviewed"
    />

    <!-- 非系統告警：單筆處置（不帶批次關聯碼；理由選填，本人觸發者亦同） -->
    <el-dialog
      v-model="singleVisible"
      :title="$t('dailyReview.drawer.single.title')"
      width="520px"
      append-to-body
      data-test="dr-alert-single-dialog"
    >
      <dl
        v-if="singleTarget"
        class="dr-single__dl"
        data-test="dr-alert-single-fields"
      >
        <dt>{{ $t('dailyReview.drawer.single.rule') }}</dt>
        <dd>
          {{ alertTypeName(singleTarget) }}<span
            v-if="isCommandRuleAlert(singleTarget)"
            class="dr-single__muted"
          >{{ $t('dailyReview.drawer.single.ruleKind') }}</span>
        </dd>
        <template v-if="singleTarget.command">
          <dt>{{ $t('dailyReview.drawer.single.command') }}</dt>
          <dd class="dr-single__mono">
            {{ singleTarget.command }}
          </dd>
        </template>
        <template v-if="singleTarget.asset_name">
          <dt>{{ $t('dailyReview.drawer.single.asset') }}</dt>
          <dd>{{ singleTarget.asset_name }}</dd>
        </template>
        <dt>{{ $t('dailyReview.drawer.single.actor') }}</dt>
        <dd>{{ userLabel(singleTarget, currentUserId) }}</dd>
        <dt>{{ $t('dailyReview.drawer.single.time') }}</dt>
        <dd>{{ dateTimeInZone(singleTarget.triggered_at, timezone) }}</dd>
      </dl>
      <el-form
        label-position="top"
        @submit.prevent
      >
        <el-form-item
          :label="$t('alerts.bulk.dispositionLabel')"
          required
        >
          <el-radio-group v-model="singleForm.disposition">
            <el-radio value="benign">
              {{ $t('alerts.dispositionBenign') }}
            </el-radio>
            <el-radio value="escalated">
              {{ $t('alerts.dispositionEscalated') }}
            </el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item :label="$t('dailyReview.drawer.single.noteLabel')">
          <el-input
            v-model="singleForm.note"
            type="textarea"
            :rows="2"
            maxlength="500"
            show-word-limit
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="singleVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          v-preview-write
          type="primary"
          :loading="singleSubmitting"
          data-test="dr-alert-single-submit"
          @click="submitSingle"
        >
          {{ $t('dailyReview.drawer.single.submit') }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { CircleCheck, ChevronDown, ChevronUp } from 'lucide-vue-next'
import { t } from '@/i18n'
import { reviewAlert } from '@/api/alerts'
import { useRoles } from '@/composables/useRoles'
import BatchCheckbox from '@/components/batch-review/BatchCheckbox.vue'
import SystemAlertDetailDrawer from '@/components/system-alert/SystemAlertDetailDrawer.vue'
import {
  ALERT_BULK_LIMIT,
  alertTargetText,
  alertTypeName,
  groupAlerts,
  isCommandRuleAlert,
  isSelfTriggered,
  isSystemAlert,
  severityLabel,
  userLabel,
} from '@/components/batch-review/alertBulk'
import { dateTimeInZone, timeInZone } from './dailyReviewFormat'
import { previewWrite as vPreviewWrite } from '@/directives/previewWrite'

const props = defineProps({
  // 該日全部未審閱告警（依觸發時間排序）
  alerts: { type: Array, default: () => [] },
  // 告警來源狀態：complete｜partial｜purged
  source: { type: String, default: 'complete' },
  total: { type: Number, default: 0 },
  benign: { type: Number, default: 0 },
  escalated: { type: Number, default: 0 },
  timezone: { type: String, default: 'UTC' },
  canSign: { type: Boolean, default: false },
})

// reviewed：逐筆處置後請父層重取；open-batch：以清單順序帶出所選的告警開處置對話框
const emit = defineEmits(['reviewed', 'open-batch'])

const SEV_TAG = { high: 'danger', medium: 'warning', low: 'info' }
// 批次列黏在告警區頂端（寫在元素上：捲動清單時已選筆數與送出動作要一直看得到）
const STICKY_STYLE = { position: 'sticky', top: '0' }

const { currentUserId } = useRoles()

const groups = computed(() => groupAlerts(props.alerts, currentUserId.value))
// 清單順序：組的順序、組內的順序（超過單次上限時，這一次處置的是前面的）
const ordered = computed(() => groups.value.flatMap((group) => group.rows))

const pendingText = computed(() => {
  const n = props.alerts.length
  const total = Math.max(props.total, n)
  return total === n
    ? t('dailyReview.drawer.alerts.pendingSame', { n })
    : t('dailyReview.drawer.alerts.pendingCount', { total, n })
})

// --- 勾選：本人觸發與別人觸發的都可以勾；目前使用者不明時不給勾 ---
const selectedIds = ref(new Set())
const isSelectable = (row) => !row.reviewed_at && currentUserId.value != null
const isSelected = (row) => selectedIds.value.has(row.id)
const selectedRows = computed(() => ordered.value.filter((row) => selectedIds.value.has(row.id)))
const selectedCount = computed(() => selectedRows.value.length)

const setSelection = (ids) => {
  selectedIds.value = new Set(ids)
}
const toggleRow = (row, checked) => {
  const next = new Set(selectedIds.value)
  if (checked && isSelectable(row)) next.add(row.id)
  else next.delete(row.id)
  setSelection(next)
}
const stateOf = (rows) => {
  const selectable = rows.filter(isSelectable)
  const picked = selectable.filter(isSelected).length
  return {
    checked: selectable.length > 0 && picked === selectable.length,
    indeterminate: picked > 0 && picked < selectable.length,
  }
}
const allState = computed(() => stateOf(props.alerts))
const groupState = (group) => stateOf(group.rows)
const toggleAll = () => {
  setSelection(allState.value.checked ? [] : props.alerts.filter(isSelectable).map((row) => row.id))
}
const toggleGroup = (group) => {
  const next = new Set(selectedIds.value)
  const select = !groupState(group).checked
  for (const row of group.rows) {
    if (select && isSelectable(row)) next.add(row.id)
    else next.delete(row.id)
  }
  setSelection(next)
}
const clearSelection = () => setSelection([])

// 重取明細後：已處置（不在清單上）的從選取移除，其餘維持勾選
watch(() => props.alerts, (list) => {
  const present = new Set(list.map((row) => row.id))
  const kept = [...selectedIds.value].filter((id) => present.has(id))
  if (kept.length !== selectedIds.value.size) setSelection(kept)
})

const selectedText = computed(() => {
  const rows = selectedRows.value
  const k = new Set(groupAlerts(rows, currentUserId.value).map((g) => g.key)).size
  const s = rows.filter((row) => isSelfTriggered(row, currentUserId.value)).length
  return s
    ? t('dailyReview.drawer.alerts.selectedSelf', { n: rows.length, k, s })
    : t('dailyReview.drawer.alerts.selected', { n: rows.length, k })
})

const openBatch = () => {
  if (selectedRows.value.length) emit('open-batch', selectedRows.value)
}

// --- 分組展開 ---
const expanded = ref(new Set())
const toggleExpand = (key) => {
  const next = new Set(expanded.value)
  if (next.has(key)) next.delete(key)
  else next.add(key)
  expanded.value = next
}

const rangeText = (group) => {
  const from = timeInZone(group.from, props.timezone)
  const to = timeInZone(group.to, props.timezone)
  return from === to ? from : `${from}–${to}`
}

// --- 列上的文字 ---
const whoLine = (row) => {
  const who = userLabel(row, currentUserId.value)
  if (!isSystemAlert(row) && row.asset_name) return t('dailyReview.drawer.alerts.whoOnAsset', { user: who, asset: row.asset_name })
  return who
}
const secondLine = (row) => {
  if (isSystemAlert(row)) {
    const target = alertTargetText(row)
    return target ? t('dailyReview.drawer.alerts.target', { target }) : ''
  }
  if (row.command) return row.command
  return isCommandRuleAlert(row) ? '' : alertTypeName(row)
}
const labelFor = (row) => {
  const parts = [timeInZone(row.triggered_at, props.timezone), userLabel(row, currentUserId.value)]
  const second = secondLine(row)
  if (second) parts.push(second)
  return parts.join('　')
}

// --- 系統告警明細：組內上一筆、下一筆；處置後換到下一筆 ---
const detailOpen = ref(false)
const detailGroupKey = ref('')
const detailId = ref(null)
const detailIds = computed(() => groups.value.find((g) => g.key === detailGroupKey.value)?.rows.map((r) => r.id) || [])
const detailPosition = computed(() => {
  const i = detailIds.value.indexOf(detailId.value)
  if (i < 0) return null
  return { index: i + 1, total: detailIds.value.length }
})
let afterReviewIndex = -1

const openDetail = (group, row) => {
  detailGroupKey.value = group.key
  detailId.value = row.id
  detailOpen.value = true
}
const stepDetail = (delta) => {
  const i = detailIds.value.indexOf(detailId.value)
  const next = detailIds.value[i + delta]
  if (next !== undefined) detailId.value = next
}
const onDetailReviewed = () => {
  afterReviewIndex = detailIds.value.indexOf(detailId.value)
  emit('reviewed')
}
// 重取後：這一筆已離開清單，換成同一位置的下一筆；這一組處置完就關閉明細
watch(detailIds, (ids) => {
  if (afterReviewIndex < 0 || !detailOpen.value) return
  if (ids.includes(detailId.value)) return
  const next = ids[Math.min(afterReviewIndex, ids.length - 1)]
  afterReviewIndex = -1
  if (next === undefined) detailOpen.value = false
  else detailId.value = next
})

// --- 非系統告警的單筆處置 ---
const singleVisible = ref(false)
const singleTarget = ref(null)
const singleForm = ref({ disposition: 'benign', note: '' })
const singleSubmitting = ref(false)

const openSingle = (row) => {
  singleTarget.value = row
  singleForm.value = { disposition: 'benign', note: '' }
  singleVisible.value = true
}

const submitSingle = async () => {
  if (!singleTarget.value) return
  singleSubmitting.value = true
  try {
    await reviewAlert(singleTarget.value.id, {
      disposition: singleForm.value.disposition,
      note: singleForm.value.note.trim(),
    })
    singleVisible.value = false
  } catch (error) {
    // 錯誤由全域攔截器提示；不論成敗都重取，畫面以伺服器現況為準
    console.error('審閱告警失敗:', error?.response?.status)
  } finally {
    singleSubmitting.value = false
    emit('reviewed')
  }
}

defineExpose({ selectedRows, clearSelection })
</script>

<style scoped>
.dr-alerts {
  padding: var(--ot-space-sm) var(--ot-space-md);
  background-color: var(--ot-bg-elevated);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}

.dr-alerts__head {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  gap: var(--ot-space-sm);
}

.dr-alerts__title {
  font-weight: 600;
  color: var(--ot-text-primary);
}

.dr-alerts__pending {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-warning);
}

.dr-alerts__hint,
.dr-alerts__sub,
.dr-alerts__notice p {
  margin: var(--ot-space-xs) 0 var(--ot-space-sm);
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
  color: var(--ot-text-secondary);
}

.dr-alerts__done {
  display: flex;
  align-items: flex-start;
  gap: var(--ot-space-sm);
}

.dr-alerts__done .dr-alerts__sub {
  margin: 2px 0 0;
}

.dr-alerts__ok {
  margin-top: 3px;
  color: var(--ot-success);
  flex: none;
}

/* 全選列／批次列：捲動清單時黏在告警區頂端 */
.dr-alerts__bar {
  z-index: 2;
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
  margin-bottom: var(--ot-space-sm);
  padding: var(--ot-space-xs) var(--ot-space-sm);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  font-size: var(--ot-font-size-sm);
}

.dr-alerts__bar--active {
  /* 黏住時清單在下方捲動：主色淡底疊在不透明的底色上，避免透出列內容 */
  background: linear-gradient(var(--ot-primary-dim), var(--ot-primary-dim)), var(--ot-bg-surface);
  border-color: var(--ot-primary);
}

.dr-alerts__bar-line {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--ot-space-xs) var(--ot-space-sm);
}

.dr-alerts__bar-line--actions :deep(.el-button + .el-button) {
  margin-left: 0;
}

.dr-alerts__bar-text {
  font-weight: 600;
  color: var(--ot-text-primary);
}

.dr-alerts__bar-aside {
  margin-left: auto;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.dr-alerts__bar-limit {
  flex: 1 1 200px;
  font-size: var(--ot-font-size-xs);
  line-height: 1.5;
  color: var(--ot-warning);
}

.dr-alerts__bar-spacer {
  flex: 1 1 0;
}

.dr-alerts__groups {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
}

.dr-group {
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  background-color: var(--ot-bg-surface);
}

.dr-group--picked {
  border-color: var(--ot-primary);
}

.dr-group__head {
  display: flex;
  align-items: flex-start;
  gap: var(--ot-space-sm);
  padding: var(--ot-space-xs) var(--ot-space-sm);
}

.dr-group__info {
  flex: 1;
  min-width: 0;
}

.dr-group__line {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--ot-space-xs) var(--ot-space-sm);
}

.dr-group__name {
  font-weight: 600;
  color: var(--ot-text-primary);
}

.dr-group__count {
  color: var(--ot-text-primary);
}

.dr-group__sub {
  margin-top: 2px;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.dr-group__self {
  color: var(--ot-info);
}

.dr-alerts__list {
  margin: 0;
  padding: 0 var(--ot-space-sm);
  list-style: none;
}

.dr-alerts__row {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  padding: 6px 0;
  border-top: 1px solid var(--ot-border-subtle);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-primary);
}

.dr-alerts__time {
  font-family: var(--ot-font-mono);
}

.dr-alerts__sev {
  min-width: 2em;
}

.dr-alerts__sev--high {
  color: var(--ot-danger);
}

.dr-alerts__sev--medium {
  color: var(--ot-warning);
}

.dr-alerts__what {
  flex: 1;
  min-width: 0;
}

.dr-alerts__who {
  word-break: break-word;
}

.dr-alerts__detail {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
  word-break: break-word;
}

.dr-alerts__detail--mono {
  font-family: var(--ot-font-mono);
  color: var(--ot-text-primary);
}

.dr-single__dl {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: var(--ot-space-xs) var(--ot-space-md);
  margin: 0 0 var(--ot-space-md);
}

.dr-single__dl dt {
  color: var(--ot-text-secondary);
}

.dr-single__dl dd {
  margin: 0;
  overflow-wrap: anywhere;
}

.dr-single__mono {
  font-family: var(--ot-font-mono);
}

.dr-single__muted {
  color: var(--ot-text-secondary);
}
</style>
