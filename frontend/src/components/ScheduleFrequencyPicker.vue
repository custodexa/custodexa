<template>
  <div class="schedule-frequency">
    <el-radio-group
      v-model="mode"
      :disabled="disabled"
      data-test="schedule-frequency-mode"
    >
      <el-radio-button
        v-for="option in modeOptions"
        :key="option"
        :value="option"
        :data-test="`schedule-mode-${option}`"
      >
        {{ $t(`scheduleFrequency.mode.${option}`) }}
      </el-radio-button>
    </el-radio-group>

    <div
      v-if="mode === NO_SCHEDULE_MODE"
      class="schedule-hint"
      data-test="schedule-none-hint"
    >
      {{ $t('scheduleFrequency.noneHint') }}
    </div>

    <div
      v-else-if="mode === CUSTOM_MODE"
      class="schedule-custom"
    >
      <el-input
        v-model="customText"
        :disabled="disabled"
        :placeholder="customPlaceholderText"
        data-test="schedule-custom-input"
      />
      <div
        v-if="customErrorText"
        class="schedule-error"
        data-test="schedule-custom-error"
      >
        {{ customErrorText }}
      </div>
      <div
        v-else
        class="schedule-hint"
      >
        {{ $t('scheduleFrequency.customHint') }}
      </div>
    </div>

    <div
      v-else
      class="schedule-fields"
    >
      <label
        v-if="mode === 'weekly'"
        class="schedule-field"
      >
        <span class="schedule-field-label">{{ $t('scheduleFrequency.weekdayLabel') }}</span>
        <el-select
          v-model="fields.weekday"
          :disabled="disabled"
          class="schedule-select"
          data-test="schedule-weekday"
        >
          <el-option
            v-for="day in WEEKDAYS"
            :key="day"
            :label="$t(`scheduleFrequency.weekday.d${day}`)"
            :value="day"
          />
        </el-select>
      </label>

      <label
        v-if="mode === 'quarterly'"
        class="schedule-field"
      >
        <span class="schedule-field-label">{{ $t('scheduleFrequency.quarterStartLabel') }}</span>
        <el-select
          v-model="fields.quarterStartMonth"
          :disabled="disabled"
          class="schedule-select schedule-select-wide"
          data-test="schedule-quarter-start"
        >
          <el-option
            v-for="start in QUARTER_START_MONTHS"
            :key="start"
            :label="quarterMonthsLabel(start)"
            :value="start"
          />
        </el-select>
      </label>

      <label
        v-if="mode === 'yearly'"
        class="schedule-field"
      >
        <span class="schedule-field-label">{{ $t('scheduleFrequency.monthLabel') }}</span>
        <el-select
          v-model="fields.month"
          :disabled="disabled"
          class="schedule-select"
          data-test="schedule-month"
        >
          <el-option
            v-for="month in MONTHS"
            :key="month"
            :label="$t('scheduleFrequency.monthValue', { month })"
            :value="month"
          />
        </el-select>
      </label>

      <label
        v-if="showDayField"
        class="schedule-field"
      >
        <span class="schedule-field-label">{{ dayFieldLabel }}</span>
        <el-select
          v-model="fields.day"
          :disabled="disabled"
          class="schedule-select"
          data-test="schedule-day"
        >
          <el-option
            v-for="day in DAYS_OF_MONTH"
            :key="day"
            :label="$t('scheduleFrequency.dayValue', { day })"
            :value="day"
          />
        </el-select>
      </label>

      <label class="schedule-field">
        <span class="schedule-field-label">{{ $t('scheduleFrequency.timeLabel') }}</span>
        <el-time-select
          v-model="timeText"
          :disabled="disabled"
          start="00:00"
          end="23:55"
          step="00:05"
          class="schedule-select"
          data-test="schedule-time"
        />
      </label>
    </div>

    <div
      v-if="summaryText"
      class="schedule-summary"
      data-test="schedule-summary"
    >
      {{ summaryText }}
    </div>

    <div
      class="schedule-preview"
      data-test="schedule-next-runs"
    >
      <span class="schedule-preview-title">{{ $t('scheduleFrequency.previewTitle') }}</span>
      <ul
        v-if="runs.length"
        class="schedule-run-list"
      >
        <li
          v-for="(run, index) in runs"
          :key="`${run}-${index}`"
          :data-test="`schedule-next-run-${index}`"
        >
          {{ formatRunTime(run) }}
        </li>
      </ul>
      <span
        v-else
        class="schedule-preview-note"
        data-test="schedule-preview-note"
      >{{ previewNote }}</span>
      <span
        v-if="runs.length && timezone"
        class="schedule-hint"
        data-test="schedule-preview-timezone"
      >{{ $t('scheduleFrequency.previewTimezone', { zone: timezone }) }}</span>
    </div>
  </div>
</template>

<script setup>
import { computed, reactive, ref, watch } from 'vue'
import { t } from '@/i18n'
import { resolveApiError } from '@/api/error'
import { getScheduleNextRuns } from '@/api/schedules'
import {
  CUSTOM_MODE,
  MONTHS,
  NO_SCHEDULE_MODE,
  QUARTER_START_MONTHS,
  SCHEDULE_MODES,
  WEEKDAYS,
  buildCron,
  cronTextIssue,
  defaultShapeFields,
  describeSchedule,
  formatClock,
  formatRunTime,
  isCronText,
  parseCron,
  quarterMonths,
} from '@/utils/cron-shape'

// 排程時刻的共用編輯器：對外的值一直是五欄排程字串，對內以「每季 1 日 00:00」
// 這種說法呈現。認不出形狀的既有值原樣落在自訂欄——本元件不會因為被掛載一次
// 就改寫任何既有排程。
const props = defineProps({
  /** 五欄排程字串；空字串代表未設定 */
  modelValue: { type: String, default: '' },
  /** 宿主是否接受「不排程」（改密計劃留空＝僅手動觸發；報告排程不接受） */
  allowEmpty: { type: Boolean, default: false },
  /** 預覽幾筆執行時刻 */
  previewCount: { type: Number, default: 3 },
  disabled: { type: Boolean, default: false },
  /** 自訂欄提示；未給時用共用文案 */
  customPlaceholder: { type: String, default: '' },
})

// update:valid 讓宿主知道現在能不能存——自訂欄寫壞時值仍然回傳（不吞掉使用者
// 打的字），但宿主的儲存鈕要能據此停用
const emit = defineEmits(['update:modelValue', 'update:valid'])

const DAYS_OF_MONTH = Array.from({ length: 31 }, (_, index) => index + 1)

const mode = ref(SCHEDULE_MODES[0])
const fields = reactive(defaultShapeFields())
const customText = ref('')

const runs = ref([])
const timezone = ref('')
const previewNote = ref('')
let previewSeq = 0

const modeOptions = computed(() =>
  props.allowEmpty ? [NO_SCHEDULE_MODE, ...SCHEDULE_MODES] : SCHEDULE_MODES
)

const showDayField = computed(() => ['monthly', 'quarterly', 'yearly'].includes(mode.value))

const dayFieldLabel = computed(() =>
  mode.value === 'quarterly'
    ? t('scheduleFrequency.quarterDayLabel')
    : t('scheduleFrequency.dayLabel')
)

const timeText = computed({
  get: () => formatClock(fields.hour, fields.minute),
  set: (value) => {
    const match = /^(\d{1,2}):(\d{1,2})$/.exec(String(value || ''))
    if (!match) return
    fields.hour = Number(match[1])
    fields.minute = Number(match[2])
  },
})

const currentCron = computed(() =>
  mode.value === CUSTOM_MODE ? customText.value.trim() : buildCron(mode.value, fields)
)

const customIssue = computed(() =>
  mode.value === CUSTOM_MODE ? cronTextIssue(customText.value) : null
)

const customErrorText = computed(() => {
  const issue = customIssue.value
  if (!issue) return ''
  return t(`scheduleFrequency.error.${issue.reason}`, {
    count: issue.count,
    index: issue.index,
    field: issue.field,
  })
})

const isValid = computed(() => {
  if (mode.value === NO_SCHEDULE_MODE) return true
  if (mode.value === CUSTOM_MODE) return isCronText(customText.value)
  return true
})

const summaryText = computed(() =>
  mode.value === NO_SCHEDULE_MODE || mode.value === CUSTOM_MODE
    ? ''
    : describeSchedule(currentCron.value)
)

const customPlaceholderText = computed(
  () => props.customPlaceholder || t('scheduleFrequency.customPlaceholder')
)

const quarterMonthsLabel = (start) => {
  const [m1, m2, m3, m4] = quarterMonths(start)
  return t('scheduleFrequency.quarterMonths', { m1, m2, m3, m4 })
}

function adopt(value) {
  const shape = parseCron(value)
  if (shape.mode === NO_SCHEDULE_MODE) {
    Object.assign(fields, defaultShapeFields())
    customText.value = ''
    // 宿主不收空值時，空白起點要換成一個存得下去的預設，否則畫面顯示著
    // 「每日 00:00」而儲存鈕永遠是停用的
    mode.value = props.allowEmpty ? NO_SCHEDULE_MODE : SCHEDULE_MODES[0]
    return
  }
  Object.assign(fields, {
    minute: shape.minute,
    hour: shape.hour,
    weekday: shape.weekday,
    day: shape.day,
    month: shape.month,
    quarterStartMonth: shape.quarterStartMonth,
  })
  customText.value = shape.mode === CUSTOM_MODE ? shape.raw : ''
  mode.value = shape.mode
}

async function refreshPreview() {
  const seq = ++previewSeq
  runs.value = []
  timezone.value = ''

  if (!currentCron.value) {
    previewNote.value = t('scheduleFrequency.previewNone')
    return
  }
  if (!isValid.value) {
    previewNote.value = t('scheduleFrequency.previewInvalid')
    return
  }

  previewNote.value = t('scheduleFrequency.previewLoading')
  try {
    const res = await getScheduleNextRuns(
      { cron: currentCron.value, count: props.previewCount },
      { skipErrorToast: true }
    )
    if (seq !== previewSeq) return
    const list = Array.isArray(res?.runs) ? res.runs : []
    runs.value = list
    timezone.value = typeof res?.timezone === 'string' ? res.timezone : ''
    previewNote.value = list.length ? '' : t('scheduleFrequency.previewUnavailable')
  } catch (err) {
    if (seq !== previewSeq) return
    // 端點說得出原因就照實顯示（格式不合），說不出就講「暫時取不到」——
    // 空白會被讀成「沒有下次執行」，那是另一件事
    previewNote.value = resolveApiError(
      err?.response?.data,
      err?.response?.status,
      t('scheduleFrequency.previewUnavailable')
    )
  }
}

watch(
  () => props.modelValue,
  (value) => {
    if (value === currentCron.value) return
    adopt(value)
  },
  { immediate: true }
)

watch(
  [currentCron, isValid],
  () => {
    if (currentCron.value !== props.modelValue) {
      emit('update:modelValue', currentCron.value)
    }
    emit('update:valid', isValid.value)
    refreshPreview()
  },
  { immediate: true }
)

defineExpose({ mode, fields, customText, runs, previewNote })
</script>

<style scoped>
.schedule-frequency {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
}

.schedule-fields {
  display: flex;
  flex-wrap: wrap;
  gap: var(--ot-space-md);
}

.schedule-field {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
}

.schedule-field-label {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.schedule-select {
  width: 130px;
}

.schedule-select-wide {
  width: 170px;
}

.schedule-summary {
  color: var(--ot-text-primary);
  font-size: var(--ot-font-size-md);
}

.schedule-hint {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

.schedule-error {
  color: var(--ot-danger);
  font-size: var(--ot-font-size-xs);
}

.schedule-preview {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
  padding: var(--ot-space-sm);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  background: var(--ot-bg-elevated);
}

.schedule-preview-title {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

.schedule-preview-note {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.schedule-run-list {
  margin: 0;
  padding-left: var(--ot-space-md);
  color: var(--ot-text-primary);
  font-family: var(--ot-font-mono);
  font-size: var(--ot-font-size-sm);
}
</style>
