<template>
  <!-- 業務時區欄位：決定每日審閱「一天」從幾點切到幾點。分界資訊（目前生效、
       待生效變更與生效日）一律取自後端，不以本機日期推算 -->
  <div
    class="dr-tz"
    :class="{ 'dr-tz--inactive': !enabled }"
    data-test="dr-tz-field"
  >
    <el-select
      :model-value="value"
      filterable
      class="dr-tz__select"
      :aria-label="label"
      :placeholder="$t('dailyReview.timezone.searchPlaceholder')"
      data-test="dr-tz-select"
      @visible-change="(open) => { if (open) expanded = true }"
      @update:model-value="(v) => $emit('update:value', v)"
    >
      <el-option
        v-for="option in options"
        :key="option.value"
        :value="option.value"
        :label="option.label"
      />
    </el-select>
    <p
      v-if="!tzState?.pending"
      class="dr-tz__explain"
      data-test="dr-tz-explain"
    >
      {{ explainText }}
    </p>
    <p
      v-if="!enabled"
      class="dr-tz__inactive-note"
      data-test="dr-tz-inactive"
    >
      {{ $t('dailyReview.timezone.disabledNote') }}
    </p>
    <div
      v-if="tzState?.pending"
      class="dr-tz__boundary"
      data-test="dr-tz-boundary"
    >
      {{ $t('dailyReview.timezone.boundary', {
        date: tzState.pending.effective_date,
        value: tzState.pending.value,
        active: `${tzState.active}（${zoneOffsetLabel(tzState.active)}）`,
      }) }}
    </div>
    <router-link
      class="dr-tz__log"
      :to="CHANGE_LOG_ROUTE"
      data-test="dr-tz-log"
    >
      {{ $t('dailyReview.timezone.changeLog') }}
    </router-link>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { t } from '@/i18n'
import { addDays, zoneOffsetLabel } from './dailyReviewFormat'
import { timezoneOptions, useTimezoneState } from './timezoneState'

const props = defineProps({
  value: { type: String, default: '' },
  // 每日審閱簽核開關（表單中的值）：關閉時欄位仍可設定，以次要樣式呈現
  enabled: { type: Boolean, default: true },
  label: { type: String, default: '' },
})

defineEmits(['update:value'])

// 沿用操作日誌頁既有的 ?resource=／?key= 落地：直接只看這個設定的變更
const CHANGE_LOG_ROUTE = Object.freeze({
  path: '/audit-logs',
  query: Object.freeze({ tab: 'logs', resource: 'security_policy', key: 'daily_review_timezone' }),
})

const { state: tzState, load } = useTimezoneState()

// 選項的 UTC 位移要逐一建立格式器，四百多個時區一次算完會卡住頁面；
// 下拉第一次打開前只算目前值那一個
const expanded = ref(false)

const names = computed(() =>
  timezoneOptions([props.value, tzState.value?.active, tzState.value?.pending?.value])
)

const optionOf = (name) => ({ value: name, label: `${name}（${zoneOffsetLabel(name)}）` })

const options = computed(() => {
  if (expanded.value) return names.value.map(optionOf)
  return props.value ? [optionOf(props.value)] : []
})

// 例句描述「昨天實際怎麼切」：日期與時區都取自後端 timezone_state（今天與目前生效的時區），
// 不用欄位的草稿值——草稿還沒存、或已存但明天才生效時，昨天仍以生效中的時區切。
// 有待生效變更時改由分界說明交代前後兩段，例句不顯示（模板 v-if）
const explainText = computed(() => {
  const today = tzState.value?.today?.date
  const active = tzState.value?.active
  if (!today || !active) return t('dailyReview.timezone.explainShort')
  const date = addDays(today, -1)
  return t('dailyReview.timezone.explain', {
    date,
    offset: zoneOffsetLabel(active, new Date(`${date}T12:00:00Z`)),
  })
})

onMounted(load)
</script>

<style scoped>
.dr-tz {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
  width: 100%;
}

.dr-tz__select {
  max-width: 320px;
}

.dr-tz__explain,
.dr-tz__inactive-note {
  margin: 0;
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
  color: var(--ot-text-secondary);
}

.dr-tz--inactive .dr-tz__select :deep(.el-select__wrapper) {
  opacity: 0.7;
}

.dr-tz__boundary {
  padding: var(--ot-space-sm) var(--ot-space-md);
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
  color: var(--ot-text-primary);
  border: 1px solid var(--ot-info);
  border-radius: var(--ot-radius-md);
  background-color: color-mix(in srgb, var(--ot-info) 10%, transparent);
}

.dr-tz__log {
  align-self: flex-start;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-primary);
  text-decoration: none;
}

.dr-tz__log:hover,
.dr-tz__log:focus-visible {
  text-decoration: underline;
}
</style>
