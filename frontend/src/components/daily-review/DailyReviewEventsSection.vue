<template>
  <!-- 登入失敗／高危操作：只列最早的 20 筆供查閱，不需處置；簽核前要看的明細
       預設展開、帶欄名。超過 20 筆時連到操作日誌，起訖取該日的實際起訖、尾端用
       排他條件（每日區間是半開區間，恰在下一日起點的事件不屬於這一天）。
       操作日誌沒有「只看這一類」的篩選，落地列的是這一天的全部操作紀錄，
       所以連結文字與說明照實寫，不承諾「全部 N 筆」 -->
  <div
    class="dr-events"
    :data-test="`dr-events-${kind}`"
  >
    <div class="dr-events__head">
      <span class="dr-events__title">{{ title }}</span>
      <span class="dr-events__hint">{{ sourceHint }}</span>
      <el-button
        v-if="list.items?.length"
        link
        type="primary"
        class="dr-events__toggle"
        @click="expanded = !expanded"
      >
        {{ expanded ? $t('dailyReview.drawer.events.collapse') : $t('dailyReview.drawer.events.expand') }}
      </el-button>
    </div>
    <table
      v-if="expanded && list.items?.length"
      class="dr-events__table"
      data-test="dr-events-table"
    >
      <thead>
        <tr>
          <th>{{ $t('dailyReview.drawer.events.columns.time') }}</th>
          <th>{{ $t('dailyReview.drawer.events.columns.user') }}</th>
          <th>{{ $t('dailyReview.drawer.events.columns.ip') }}</th>
          <th>{{ kind === 'login_failures' ? $t('dailyReview.drawer.events.columns.reason') : $t('dailyReview.drawer.events.columns.operation') }}</th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="item in list.items"
          :key="item.id"
        >
          <td class="dr-events__time">
            {{ timeInZone(item.created_at, timezone) }}
          </td>
          <td>{{ item.username || '-' }}</td>
          <td>{{ item.client_ip || '' }}</td>
          <td class="dr-events__msg">
            {{ item.error_msg || item.path }}
          </td>
        </tr>
      </tbody>
    </table>
    <a
      v-if="showViewAll"
      class="dr-events__all"
      data-test="dr-events-view-all"
      :href="href"
      @click.exact.prevent="$emit('navigate', location)"
    >
      {{ $t('dailyReview.drawer.events.viewAll') }}
    </a>
    <p
      v-if="showViewAll"
      class="dr-events__all-hint"
      data-test="dr-events-view-all-hint"
    >
      {{ $t(`dailyReview.drawer.events.viewAllHint.${kind}`, { shown: list.items?.length ?? 0, n: list.total }) }}
    </p>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import { t } from '@/i18n'
import { countText, timeInZone } from './dailyReviewFormat'

const props = defineProps({
  kind: { type: String, required: true }, // login_failures | high_risk_ops
  // { total, items[≤20], source_status }
  list: { type: Object, required: true },
  // 快照語義的計數（purged 為 null）
  count: { type: [Number, null], default: null },
  timezone: { type: String, default: 'UTC' },
  windowStart: { type: String, required: true },
  windowEnd: { type: String, required: true },
})

defineEmits(['navigate'])

const expanded = ref(true)

const title = computed(() => {
  const text = countText(props.count ?? (props.list.source_status === 'purged' ? null : props.list.total), props.list.source_status)
  return props.kind === 'login_failures'
    ? t('dailyReview.drawer.events.loginFailures', { count: text })
    : t('dailyReview.drawer.events.highRiskOps', { count: text })
})

const sourceHint = computed(() => {
  if (props.list.source_status === 'purged') return t('dailyReview.drawer.events.purged')
  if (props.list.source_status === 'partial') return t('dailyReview.drawer.events.partial')
  return t('dailyReview.drawer.events.readOnly')
})

const showViewAll = computed(() => (props.list.total ?? 0) > (props.list.items?.length ?? 0))

// 操作日誌頁認 start_time＋end_before（排他尾端）。不用 end_time：它含尾端，
// 會把恰在下一日 00:00、屬於下一天的事件也列進來
const location = computed(() => ({
  path: '/audit-logs',
  query: { tab: 'logs', start_time: props.windowStart, end_before: props.windowEnd },
}))
const href = computed(() => {
  const q = new URLSearchParams(location.value.query)
  return `/audit-logs?${q.toString()}`
})
</script>

<style scoped>
.dr-events {
  padding: var(--ot-space-sm) var(--ot-space-md);
  background-color: var(--ot-bg-elevated);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}

.dr-events__head {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: var(--ot-space-sm);
}

.dr-events__title {
  font-weight: 600;
  color: var(--ot-text-primary);
}

.dr-events__hint {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.dr-events__toggle {
  margin-left: auto;
}

.dr-events__table {
  width: 100%;
  margin-top: var(--ot-space-sm);
  border-collapse: collapse;
  font-size: var(--ot-font-size-sm);
}

.dr-events__table td {
  padding: 4px var(--ot-space-xs);
  border-top: 1px solid var(--ot-border-subtle);
  color: var(--ot-text-primary);
}

.dr-events__table th {
  padding: 4px var(--ot-space-xs);
  font-size: var(--ot-font-size-xs);
  font-weight: normal;
  text-align: left;
  color: var(--ot-text-secondary);
}

.dr-events__time {
  white-space: nowrap;
  font-family: var(--ot-font-mono);
}

.dr-events__msg {
  word-break: break-word;
}

.dr-events__all {
  display: inline-block;
  margin-top: var(--ot-space-sm);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-primary);
  text-decoration: none;
}

.dr-events__all-hint {
  margin: var(--ot-space-xs) 0 0;
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
  color: var(--ot-text-secondary);
}

.dr-events__all:hover,
.dr-events__all:focus-visible {
  text-decoration: underline;
}
</style>
