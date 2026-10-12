<template>
  <!-- 未審閱告警：處置方式與告警頁的批次審閱相同（勾選多筆、共用一個理由、逐筆送出）。
       自己連線觸發的告警不收進批次（後端也會擋），改逐筆審閱。
       每處置完一批就請父層重取該日明細——按鈕能不能按以伺服器的數字為準 -->
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
        >{{ $t('dailyReview.drawer.alerts.pendingCount', { total: Math.max(total, alerts.length), n: alerts.length }) }}</span>
      </div>
      <p
        v-if="canSign"
        class="dr-alerts__hint"
      >
        {{ $t('dailyReview.drawer.alerts.hint') }}
      </p>
      <BatchSelectionBar
        v-if="canSign && selection.selected.value.length"
        test-id="dr-alerts-batch-bar"
        :count-text="$t('dailyReview.drawer.alerts.selected', { n: selection.selected.value.length })"
        :clear-text="$t('alerts.batch.clear')"
        @clear="selection.clear()"
      >
        <el-button
          type="primary"
          data-test="dr-alerts-batch-open"
          @click="batchDialogRef?.open()"
        >
          {{ $t('dailyReview.drawer.alerts.batchOpen') }}
        </el-button>
      </BatchSelectionBar>
      <ul class="dr-alerts__list">
        <li
          v-for="row in alerts"
          :key="row.id"
          class="dr-alerts__row"
          :data-test="`dr-alert-${row.id}`"
        >
          <BatchCheckbox
            v-if="canSign"
            test-id="dr-alert-select"
            :data-id="row.id"
            :checked="selection.isSelected(row)"
            :disabled="!selection.canToggle(row, isSelectable)"
            :label="isSelf(row) ? $t('alerts.batch.selfTriggeredTip') : $t('alerts.batch.selectRow', { label: labelFor(row) })"
            @change="(checked) => selection.toggle(row, checked)"
          />
          <span class="dr-alerts__time">{{ timeInZone(row.triggered_at, timezone) }}</span>
          <span :class="['dr-alerts__sev', `dr-alerts__sev--${row.severity}`]">{{ severityLabel(row.severity) }}</span>
          <span class="dr-alerts__rule">{{ ruleText(row) }}</span>
          <el-button
            v-if="canSign && isSelf(row)"
            link
            type="primary"
            size="small"
            data-test="dr-alert-single"
            :title="$t('alerts.batch.selfTriggeredTip')"
            @click="openSingle(row)"
          >
            {{ $t('dailyReview.drawer.alerts.single') }}
          </el-button>
          <span
            v-else
            class="dr-alerts__state"
          >{{ $t('dailyReview.drawer.alerts.unreviewed') }}</span>
        </li>
      </ul>
    </template>

    <AlertBatchReviewDialog
      v-if="canSign"
      ref="batchDialogRef"
      :alerts="selection.selected.value"
      :current-user-id="currentUserId"
      :label-for="labelFor"
      @settled="onBatchSettled"
      @finished="onBatchFinished"
    />

    <!-- 本人觸發的告警：單筆審閱（不帶批次關聯碼） -->
    <el-dialog
      v-model="singleVisible"
      :title="$t('dailyReview.drawer.single.title')"
      width="480px"
      append-to-body
      data-test="dr-alert-single-dialog"
    >
      <p class="dr-alerts__single-target">
        {{ singleTarget ? labelFor(singleTarget) : '' }}
      </p>
      <el-form
        label-position="top"
        @submit.prevent
      >
        <el-form-item
          :label="$t('alerts.dispositionLabel')"
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
            :rows="3"
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
import { ref } from 'vue'
import { CircleCheck } from 'lucide-vue-next'
import { t } from '@/i18n'
import { reviewAlert } from '@/api/alerts'
import { useRoles } from '@/composables/useRoles'
import { useBatchSelection } from '@/composables/useBatchReview'
import BatchSelectionBar from '@/components/batch-review/BatchSelectionBar.vue'
import BatchCheckbox from '@/components/batch-review/BatchCheckbox.vue'
import AlertBatchReviewDialog from '@/components/batch-review/AlertBatchReviewDialog.vue'
import { alertRuleText } from '@/constants/command-degrade'
import { timeInZone } from './dailyReviewFormat'

const props = defineProps({
  // 該日全部未審閱告警
  alerts: { type: Array, default: () => [] },
  // 告警來源狀態：complete｜partial｜purged
  source: { type: String, default: 'complete' },
  total: { type: Number, default: 0 },
  benign: { type: Number, default: 0 },
  escalated: { type: Number, default: 0 },
  timezone: { type: String, default: 'UTC' },
  canSign: { type: Boolean, default: false },
})

const emit = defineEmits(['reviewed'])

const { currentUserId } = useRoles()
const selection = useBatchSelection()
const batchDialogRef = ref(null)

const isSelf = (row) => currentUserId.value != null && row.user_id === currentUserId.value
// 目前使用者不明時一律不給勾（後端也會擋）
const isSelectable = (row) => !row.reviewed_at && currentUserId.value != null && !isSelf(row)

const SEVERITIES = ['high', 'medium', 'low']
const severityLabel = (severity) =>
  SEVERITIES.includes(severity) ? t(`enum.alertLevel.${severity}`) : severity

// 非規則類告警的 rule_name 是機器碼，沿用告警頁的散文（與首頁共用）
const ruleText = alertRuleText
const labelFor = (row) => `${ruleText(row)} · ${timeInZone(row.triggered_at, props.timezone)}`

// 一批送完、結果列出現時就重取該日明細（不等使用者按「完成」），
// 上方的待處置筆數與簽核按鈕才不會停在送出前的狀態
let refreshedOnSettle = false
const onBatchSettled = () => {
  selection.clear()
  refreshedOnSettle = true
  emit('reviewed')
}

const onBatchFinished = () => {
  selection.clear()
  if (!refreshedOnSettle) emit('reviewed')
  refreshedOnSettle = false
}

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
    console.error('審閱告警失敗:', error)
  } finally {
    singleSubmitting.value = false
    emit('reviewed')
  }
}

defineExpose({ selection, isSelectable })
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

.dr-alerts__list {
  margin: 0;
  padding: 0;
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

.dr-alerts__rule {
  flex: 1;
  min-width: 0;
  word-break: break-word;
}

.dr-alerts__state {
  color: var(--ot-warning);
}

.dr-alerts__single-target {
  margin: 0 0 var(--ot-space-sm);
  color: var(--ot-text-secondary);
}
</style>
