<template>
  <div
    class="check-summary"
    data-test="bulk-check-summary"
  >
    <div
      class="banner"
      :class="state"
      :data-test="`bulk-banner-${state}`"
    >
      {{ bannerText }}
    </div>

    <template v-if="showDetails">
      <div class="filters">
        <el-check-tag
          v-for="f in FILTERS"
          :key="f.value"
          :checked="filter === f.value"
          :data-test="`bulk-filter-${f.value}`"
          @change="emit('update:filter', f.value)"
        >
          {{ t(f.label, { n: f.count() }) }}
        </el-check-tag>
      </div>
    </template>
  </div>
</template>

<script setup>
/**
 * 檢查結果摘要：通過（綠）、有錯（紅＋列篩選）、內容已變更（灰）、
 * 寫入時狀態已變（紅，409 回到檢查步驟）。錯誤清單另見 BulkErrorList
 */
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

const props = defineProps({
  // passed | errors | stale | stateChanged
  state: { type: String, required: true },
  summary: { type: Object, required: true },
  filter: { type: String, default: 'all' },
})

const emit = defineEmits(['update:filter'])

const { t } = useI18n()

const FILTERS = [
  { value: 'all', label: 'assets.bulk.filterAll', count: () => props.summary.total },
  { value: 'invalid', label: 'assets.bulk.filterInvalid', count: () => props.summary.invalid },
  { value: 'valid', label: 'assets.bulk.filterValid', count: () => props.summary.valid },
]

const showDetails = computed(() => props.state === 'errors' || props.state === 'stateChanged')

const bannerText = computed(() => {
  const s = props.summary
  switch (props.state) {
    case 'passed':
      return t('assets.bulk.allPassed', { total: s.total, pending: s.pending })
    case 'errors':
      return t('assets.bulk.hasErrors', { total: s.total, invalid: s.invalid })
    case 'stateChanged':
      return t('assets.bulk.stateChanged')
    default:
      return t('assets.bulk.stale')
  }
})
</script>

<style scoped>
.check-summary {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
}

.banner {
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
}

.banner.passed {
  color: var(--ot-success);
  border-color: color-mix(in srgb, var(--ot-success) 45%, transparent);
  background: color-mix(in srgb, var(--ot-success) 12%, transparent);
}

.banner.errors,
.banner.stateChanged {
  color: var(--ot-danger);
  border-color: color-mix(in srgb, var(--ot-danger) 45%, transparent);
  background: color-mix(in srgb, var(--ot-danger) 12%, transparent);
}

.banner.stale {
  color: var(--ot-text-secondary);
}

.filters {
  display: flex;
  gap: var(--ot-space-sm);
}

/* 列篩選是切換鈕不是狀態標籤：未選中為中性外框，選中填主色 */
.filters :deep(.el-check-tag) {
  padding: 4px 12px;
  border: 1px solid var(--ot-border);
  border-radius: 999px;
  background: transparent;
  color: var(--ot-text-primary);
  font-weight: 500;
}

.filters :deep(.el-check-tag.is-checked) {
  border-color: var(--el-color-primary);
  background: var(--el-color-primary);
  color: var(--ot-bg-page);
}
</style>
