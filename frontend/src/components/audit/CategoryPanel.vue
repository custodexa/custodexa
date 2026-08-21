<template>
  <div
    class="category-panel"
    data-test="category-panel"
  >
    <div class="panel-head">
      <span class="panel-title">{{ $t('auditorWorkbench.categories.title') }}</span>
      <span class="panel-ops">
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
    </div>

    <ul class="category-list">
      <li
        v-for="type in TIMELINE_TYPES"
        :key="type"
        class="category-item"
        :data-test="`category-${type}`"
      >
        <el-checkbox
          :model-value="modelValue.includes(type)"
          @change="toggle(type, $event)"
        >
          {{ typeLabel(type) }}
        </el-checkbox>
        <span class="category-meta">
          <span
            class="category-count"
            :data-test="`count-${type}`"
          >{{ countOf(type) }}</span>
          <!--
            coverage 徽章與筆數並列：只給筆數會讓「0 筆」在三種完全不同的
            成因（真的沒發生／已清除／無保留政策）之間無從分辨
          -->
          <el-tag
            size="small"
            :type="badgeType(modelValue.includes(type) ? stateOf(type) : 'not_queried')"
            :data-test="`coverage-badge-${type}`"
          >
            {{ badgeText(type) }}
          </el-tag>
        </span>
      </li>
    </ul>

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

const props = defineProps({
  // 開啟中的類別；**關閉的類別不送查詢**（types 參數隨之縮減）
  modelValue: { type: Array, default: () => [] },
  counts: { type: Object, default: () => ({}) },
  coverage: { type: Array, default: () => [] },
})
const emit = defineEmits(['update:modelValue'])

const { t } = useI18n()

const isOn = (type) => props.modelValue.includes(type)

// 關閉的類別根本沒查過：顯示 0 會被讀成「這段時間沒發生」，而那是三種
// 完全不同的事實之一。未查詢就寫未查詢
const countOf = (type) => (isOn(type) ? (props.counts?.[type] ?? 0) : '—')

const stateOf = (type) =>
  props.coverage?.find((c) => c.type === type)?.state || 'present'

const badgeType = (state) => {
  if (state === 'purged') return 'warning'
  if (state === 'not_retained' || state === 'not_queried') return 'info'
  return 'success'
}

const badgeText = (type) =>
  isOn(type)
    ? t(`auditorWorkbench.coverage.badge.${stateOf(type)}`)
    : t('auditorWorkbench.categories.notQueried')

const toggle = (type, checked) => {
  const next = checked
    ? [...props.modelValue, type].filter((v, i, arr) => arr.indexOf(v) === i)
    : props.modelValue.filter((v) => v !== type)
  // 依固定值域排序，讓 URL 的 types 參數對同一組選擇恆等（可比對、可快取）
  emit(
    'update:modelValue',
    TIMELINE_TYPES.filter((v) => next.includes(v))
  )
}
</script>

<style scoped>
.category-panel {
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: var(--ot-space-sm);
}

.panel-title {
  font-size: var(--ot-font-size-md);
  color: var(--ot-text-primary);
  font-weight: 600;
}

.category-list {
  list-style: none;
  margin: 0;
  padding: 0;
}

.category-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--ot-space-sm);
  padding: 2px 0;
}

.category-meta {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
}

.category-count {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  font-variant-numeric: tabular-nums;
}

.all-off {
  margin: var(--ot-space-sm) 0 0;
  color: var(--ot-warning);
  font-size: var(--ot-font-size-xs);
}
</style>
