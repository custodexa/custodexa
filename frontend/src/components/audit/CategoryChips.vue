<template>
  <div
    class="category-chips"
    data-test="category-chips"
  >
    <span class="chips-label">{{ $t('auditorWorkbench.categories.title') }}</span>

    <el-popover
      v-for="type in TIMELINE_TYPES"
      :key="type"
      placement="bottom-start"
      :width="380"
      trigger="hover"
      :show-after="200"
      popper-class="category-chip-popper"
    >
      <template #reference>
        <button
          type="button"
          class="chip"
          :class="{ 'is-on': isOn(type) }"
          :aria-pressed="isOn(type) ? 'true' : 'false'"
          :data-test="`category-${type}`"
          @click="toggle(type)"
        >
          <span class="chip-label">{{ typeLabel(type) }}</span>
          <span
            class="chip-count"
            :data-test="`count-${type}`"
          >{{ countOf(type) }}</span>
          <!--
            coverage 徽章與筆數並列：只給筆數會讓「0 筆」在三種完全不同的
            成因（真的沒發生／已清除／無保留政策）之間無從分辨。
            完整說明句掛在本 chip 的 popover 上（原常駐 alert 退場，語義不減）
          -->
          <el-tag
            size="small"
            :type="badgeType(isOn(type) ? stateOf(type) : 'not_queried')"
            :data-test="`coverage-badge-${type}`"
          >
            {{ badgeText(type) }}
          </el-tag>
        </button>
      </template>

      <div
        class="chip-detail"
        :data-test="detailTestId(type)"
      >
        <p class="chip-detail-text">
          {{ detailText(type) }}
        </p>
        <!-- 清除區間的查核入口：說明可以收進 popover，動作不可以消失 -->
        <el-button
          v-if="noticeOf(type)?.seqRange"
          link
          type="primary"
          size="small"
          :data-test="`checkpoint-link-${type}`"
          @click="emit('open-checkpoint', noticeOf(type).seqRange)"
        >
          {{ $t('auditorWorkbench.coverage.checkpointLink', {
            from: noticeOf(type).seqRange.from,
            to: noticeOf(type).seqRange.to,
          }) }}
        </el-button>
      </div>
    </el-popover>

    <span class="chips-ops">
      <el-button
        link
        size="small"
        data-test="select-all"
        @click="emit('update:modelValue', [...TIMELINE_TYPES])"
      >
        {{ $t('auditorWorkbench.categories.selectAll') }}
      </el-button>
      <el-button
        link
        size="small"
        data-test="clear-all"
        @click="emit('update:modelValue', [])"
      >
        {{ $t('auditorWorkbench.categories.clearAll') }}
      </el-button>
    </span>

    <p
      v-if="modelValue.length === 0"
      class="all-off"
      data-test="all-off-hint"
    >
      {{ $t('auditorWorkbench.categories.allOff') }}
    </p>
  </div>
</template>

<script setup>
import { useI18n } from 'vue-i18n'
import { TIMELINE_TYPES, typeLabel } from './timelineSummary'
import { coverageNotice, coverageState } from './coverageNotice'

// 類別篩選列（原左欄 CategoryPanel 的替代形態）。
//
// 併入篩選列的理由：類別選擇是**篩選動作**，不是常駐資訊面板；獨立側欄
// 讓它佔掉整條左欄，把主角（事件明細）擠成一個小窗。chip 一顆同時承載
// 三件事——開關、筆數、覆蓋狀態徽章——完整說明句改由 popover 承載
const props = defineProps({
  // 開啟中的類別；**關閉的類別不送查詢**（types 參數隨之縮減）
  modelValue: { type: Array, default: () => [] },
  counts: { type: Object, default: () => ({}) },
  coverage: { type: Array, default: () => [] },
})
const emit = defineEmits(['update:modelValue', 'open-checkpoint'])

const { t } = useI18n()

const isOn = (type) => props.modelValue.includes(type)

// 關閉的類別根本沒查過：顯示 0 會被讀成「這段時間沒發生」，而那是三種
// 完全不同的事實之一。未查詢就寫未查詢
const countOf = (type) => (isOn(type) ? (props.counts?.[type] ?? 0) : '—')

const stateOf = (type) => coverageState(props.coverage, type)

const badgeType = (state) => {
  if (state === 'purged') return 'warning'
  if (state === 'not_retained' || state === 'not_queried') return 'info'
  return 'success'
}

const badgeText = (type) =>
  isOn(type)
    ? t(`auditorWorkbench.coverage.badge.${stateOf(type)}`)
    : t('auditorWorkbench.categories.notQueried')

// 開啟中的類別才有覆蓋狀態可談；關掉的類別沒查過，任何「清除／未清除」
// 的斷言都是無中生有
const noticeOf = (type) =>
  isOn(type) ? coverageNotice(type, { coverage: props.coverage, counts: props.counts, t }) : null

// popover 內容：三種需要標記的空白照原句給；present 且有資料只報筆數；
// 未納入查詢明說「沒查過不等於沒發生」
const detailText = (type) => {
  const notice = noticeOf(type)
  if (notice) return notice.text
  const category = typeLabel(type)
  if (!isOn(type)) return t('auditorWorkbench.categories.notQueriedDetail', { category })
  return t('auditorWorkbench.categories.countLine', {
    category,
    count: props.counts?.[type] ?? 0,
  })
}

// 有標記的三態沿用原 data-test（coverage-<state>-<type>），使既有斷言
// 逐條對得上；沒有標記需求的兩種情形另立 id，不冒充成 coverage 標記
const detailTestId = (type) => {
  const notice = noticeOf(type)
  return notice ? `coverage-${notice.state}-${type}` : `chip-detail-${type}`
}

const toggle = (type) => {
  const next = isOn(type)
    ? props.modelValue.filter((v) => v !== type)
    : [...props.modelValue, type]
  // 依固定值域排序，讓 URL 的 types 參數對同一組選擇恆等（可比對、可快取）
  emit(
    'update:modelValue',
    TIMELINE_TYPES.filter((v) => next.includes(v))
  )
}
</script>

<style scoped>
.category-chips {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: var(--ot-space-xs);
  width: 100%;
}

.chips-label {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  margin-right: var(--ot-space-xs);
}

.chip {
  display: inline-flex;
  align-items: center;
  gap: var(--ot-space-xs);
  padding: 2px var(--ot-space-sm);
  border: 1px solid var(--ot-border-subtle);
  border-radius: 999px;
  background-color: transparent;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 22px;
  cursor: pointer;
}

.chip:hover {
  border-color: var(--ot-primary);
}

.chip:focus-visible {
  outline: 2px solid var(--ot-primary-hover);
}

/* 開／關兩態必須一眼分得出來：關掉的類別不進查詢，看錯等於看漏資料 */
.chip.is-on {
  border-color: var(--ot-primary);
  background-color: var(--ot-primary-dim);
  color: var(--ot-text-primary);
}

.chip-count {
  font-variant-numeric: tabular-nums;
}

.chips-ops {
  margin-left: auto;
  display: inline-flex;
  align-items: center;
  gap: var(--ot-space-xs);
}

.all-off {
  flex-basis: 100%;
  margin: 0;
  color: var(--ot-warning);
  font-size: var(--ot-font-size-xs);
}

.chip-detail-text {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
  color: var(--ot-text-primary);
}
</style>
