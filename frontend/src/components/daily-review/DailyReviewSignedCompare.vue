<template>
  <!-- 已簽日的唯讀對照：簽核時固化的計數與目前可查的筆數分開列，
       簽核之後才寫入的未審閱告警另外說明（簽核紀錄不改寫）；
       升級前的簽核分不出簽核前後，只說此刻仍未審閱 -->
  <div
    class="dr-compare"
    data-test="dr-compare"
  >
    <div class="dr-compare__title">
      {{ $t('dailyReview.drawer.compare.title') }}
      <span
        v-if="legacy"
        class="dr-compare__legacy"
        data-test="dr-compare-legacy"
      >{{ $t('dailyReview.drawer.record.legacy') }}</span>
    </div>
    <table class="dr-compare__table">
      <thead>
        <tr>
          <th>{{ $t('dailyReview.drawer.compare.item') }}</th>
          <th>{{ $t('dailyReview.drawer.compare.atSign') }}</th>
          <th>{{ $t('dailyReview.drawer.compare.now') }}</th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="row in rows"
          :key="row.key"
        >
          <td>
            {{ row.label }}
            <span
              v-if="row.criteriaChanged"
              class="dr-compare__tag"
              data-test="dr-compare-criteria-tag"
            >{{ $t('dailyReview.drawer.compare.criteriaTag') }}</span>
          </td>
          <td>{{ row.atSign }}</td>
          <td
            :class="{ 'dr-compare__diff': row.changed }"
            :data-test="`dr-compare-now-${row.key}`"
          >
            {{ row.now }}
          </td>
        </tr>
      </tbody>
    </table>
    <p class="dr-compare__hint">
      {{ $t('dailyReview.drawer.compare.hint') }}
    </p>
    <!-- 判準版本不同：兩欄依不同口徑計算，差異不是紀錄被改動 -->
    <div
      v-if="criteriaChanged"
      class="dr-compare__criteria"
      data-test="dr-compare-criteria"
    >
      <Info
        class="dr-compare__criteria-icon"
        :size="16"
        aria-hidden="true"
      />
      <span>{{ $t('dailyReview.drawer.compare.criteriaChanged') }}</span>
    </div>

    <div
      v-if="alertsAfterSign > 0"
      class="dr-compare__after"
      data-test="dr-after-sign"
    >
      <div class="dr-compare__after-head">
        <span>{{ $t('dailyReview.drawer.afterSign.title', { n: alertsAfterSign }) }}</span>
        <a
          href="/alerts"
          data-test="dr-after-sign-link"
          @click.exact.prevent="$emit('navigate', '/alerts')"
        >{{ $t('dailyReview.drawer.afterSign.link') }}</a>
      </div>
      <p>{{ $t('dailyReview.drawer.afterSign.body') }}</p>
    </div>

    <!-- 升級前的簽核不檢查告警處置：此刻仍未審閱的告警分不出簽核前後，不說成「簽核後出現」 -->
    <div
      v-else-if="legacyUnreviewed > 0"
      class="dr-compare__after"
      data-test="dr-legacy-unreviewed"
    >
      <div class="dr-compare__after-head">
        <span>{{ $t('dailyReview.drawer.afterSign.legacyTitle', { n: legacyUnreviewed }) }}</span>
        <a
          href="/alerts"
          data-test="dr-legacy-unreviewed-link"
          @click.exact.prevent="$emit('navigate', '/alerts')"
        >{{ $t('dailyReview.drawer.afterSign.link') }}</a>
      </div>
      <p>{{ $t('dailyReview.drawer.afterSign.legacyBody') }}</p>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { Info } from 'lucide-vue-next'
import { t } from '@/i18n'
import { countText } from './dailyReviewFormat'

const props = defineProps({
  // 簽核時固化的快照（新形或舊形）
  signedSnapshot: { type: Object, default: () => ({}) },
  // 單日明細：目前可查的總數與來源狀態
  detail: { type: Object, required: true },
  legacy: { type: Boolean, default: false },
})

defineEmits(['navigate'])

const alertsAfterSign = computed(() => Number(props.detail.alerts_after_sign) || 0)
// 舊制列的 alerts_after_sign 恆為 null：只說此刻仍未審閱幾筆，不推論出現在簽核之後
const legacyUnreviewed = computed(() =>
  props.legacy && props.detail.alerts_after_sign == null ? (props.detail.unreviewed_alerts?.length || 0) : 0,
)

// 簽核快照沒有版本鍵＝判準版本 1；單日明細的 counts 帶現行版本
const criteriaVersion = (value) => Number(value) || 1
const criteriaChanged = computed(() =>
  criteriaVersion(props.signedSnapshot?.high_risk_criteria) !== criteriaVersion(props.detail.counts?.high_risk_criteria),
)

const nowCount = (list) => countText(list?.source_status === 'purged' ? null : list?.total, list?.source_status)

const rows = computed(() => {
  const s = props.signedSnapshot || {}
  const counts = props.detail.counts || {}
  // 告警列「簽核時」多一段「（都已處置）」的說明，比對只看計數本身：
  // 著色代表「與簽核時不同」，相同（例如 0 與 0）就不著色
  const alertsAtSignCount = s.alerts_total !== undefined
    ? countText(s.alerts_total, s.alerts_source)
    : countText(s.unreviewed_alerts, s.alerts_source)
  const alertsAtSign = s.alerts_total !== undefined && s.alerts_source !== 'purged'
    ? `${alertsAtSignCount}${t('dailyReview.drawer.compare.allReviewed')}`
    : alertsAtSignCount
  const loginAtSign = countText(s.login_failures, s.login_failures_source)
  const loginNow = nowCount(props.detail.login_failures)
  const alertsNow = countText(counts.alerts_total ?? counts.unreviewed_alerts, counts.alerts_source)
  const highAtSign = countText(s.high_risk_ops, s.high_risk_ops_source)
  const highNow = nowCount(props.detail.high_risk_ops)
  return [
    { key: 'login', label: t('common.loginFailures'), atSign: loginAtSign, now: loginNow, changed: loginAtSign !== loginNow },
    {
      key: 'alerts',
      label: t('dailyReview.drawer.compare.alerts'),
      atSign: alertsAtSign,
      now: alertsNow,
      changed: alertsAtSignCount !== alertsNow,
    },
    {
      key: 'high',
      label: t('common.highRiskOps'),
      atSign: highAtSign,
      now: highNow,
      changed: !criteriaChanged.value && highAtSign !== highNow,
      criteriaChanged: criteriaChanged.value,
    },
  ]
})
</script>

<style scoped>
.dr-compare__title {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-sm);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.dr-compare__legacy {
  font-size: var(--ot-font-size-xs);
  font-weight: normal;
  color: var(--ot-warning);
}

.dr-compare__table {
  width: 100%;
  border-collapse: collapse;
  font-size: var(--ot-font-size-sm);
}

.dr-compare__table th,
.dr-compare__table td {
  padding: 6px var(--ot-space-sm);
  text-align: left;
  border-bottom: 1px solid var(--ot-border-subtle);
  color: var(--ot-text-primary);
}

.dr-compare__table th {
  font-weight: normal;
  color: var(--ot-text-secondary);
  background-color: var(--ot-bg-elevated);
}

.dr-compare__tag {
  display: inline-block;
  margin-left: var(--ot-space-xs);
  padding: 0 6px;
  font-size: var(--ot-font-size-xs);
  line-height: 18px;
  color: var(--ot-text-secondary);
  border: 1px solid var(--ot-border);
  border-radius: var(--ot-radius-sm);
}

.dr-compare__criteria {
  display: flex;
  align-items: flex-start;
  gap: var(--ot-space-sm);
  margin-top: var(--ot-space-sm);
  padding: var(--ot-space-sm) var(--ot-space-md);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
  color: var(--ot-text-primary);
  background-color: var(--ot-primary-dim);
  border-radius: var(--ot-radius-md);
}

.dr-compare__criteria-icon {
  flex-shrink: 0;
  margin-top: 2px;
  color: var(--ot-primary);
}

.dr-compare__diff {
  color: var(--ot-warning) !important;
}

.dr-compare__hint,
.dr-compare__after p {
  margin: var(--ot-space-sm) 0 0;
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
  color: var(--ot-text-secondary);
}

.dr-compare__after {
  margin-top: var(--ot-space-md);
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--ot-warning);
  border-radius: var(--ot-radius-md);
}

.dr-compare__after-head {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  gap: var(--ot-space-sm);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.dr-compare__after-head a {
  font-weight: normal;
  color: var(--ot-primary);
  text-decoration: none;
}
</style>
