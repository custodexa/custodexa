<template>
  <!-- 固化的簽核紀錄：送出後、搶先簽核時與已簽日的唯讀抽屜共用。
       簽核時間一律取伺服器寫入的值，以該列自己的切日時區呈現 -->
  <div
    class="dr-record"
    data-test="dr-record"
  >
    <div class="dr-record__head">
      <span class="dr-record__title">{{ $t('dailyReview.drawer.record.title') }}</span>
      <span class="dr-record__fixed">{{ $t('dailyReview.drawer.record.fixed') }}</span>
    </div>
    <dl class="dr-record__list">
      <dt>{{ $t('dailyReview.drawer.record.date') }}</dt>
      <dd>
        {{ $t('dailyReview.drawer.record.dateValue', { date: record.review_date, offset: cutOffset }) }}
        <el-tag
          v-if="isInferredBasis(record.enabled_basis)"
          size="small"
          type="info"
          class="dr-record__tag"
          data-test="dr-record-inferred"
        >
          {{ $t('dailyReview.enabledInferred.tag') }}
        </el-tag>
        <div
          v-if="record.timezone_inferred"
          class="dr-record__sub"
        >
          {{ $t('dailyReview.drawer.record.tzInferred') }}
        </div>
      </dd>
      <dt>{{ $t('dailyReview.drawer.record.signedAt') }}</dt>
      <dd data-test="dr-record-signed-at">
        {{ formatInZone(record.signed_at, record.timezone, { seconds: true }) }}
      </dd>
      <dt>{{ $t('dailyReview.drawer.record.type') }}</dt>
      <dd>
        <el-tag
          size="small"
          :type="record.late ? 'warning' : 'success'"
          data-test="dr-record-type"
        >
          {{ record.late
            ? $t('dailyReview.workspace.typeLate', { n: record.late_days ?? '—' })
            : $t('dailyReview.workspace.typeOnTime') }}
        </el-tag>
      </dd>
      <dt>{{ $t('dailyReview.drawer.record.signer') }}</dt>
      <dd>{{ record.reviewer_name }}</dd>
      <template v-if="record.late">
        <dt>{{ $t('dailyReview.drawer.record.delay') }}</dt>
        <dd class="dr-record__text">
          {{ record.delay_reason || $t('dailyReview.workspace.remarkNone') }}
        </dd>
      </template>
      <template v-else>
        <dt>{{ $t('dailyReview.drawer.record.note') }}</dt>
        <dd class="dr-record__text">
          {{ record.note || $t('dailyReview.workspace.remarkNone') }}
        </dd>
      </template>
      <template v-if="showCounts">
        <dt>{{ $t('dailyReview.drawer.record.counts') }}</dt>
        <dd>
          {{ $t('dailyReview.workspace.countsLine', countItems) }}
          <div
            v-if="record.coverage === 'until_signed'"
            class="dr-record__sub"
            data-test="dr-record-legacy"
          >
            {{ $t('dailyReview.drawer.record.legacy') }}
          </div>
        </dd>
        <dt>{{ $t('dailyReview.drawer.record.disposition') }}</dt>
        <dd>{{ dispositionText }}</dd>
      </template>
    </dl>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { t } from '@/i18n'
import {
  countText,
  formatInZone,
  isInferredBasis,
  offsetLabel,
  parseSnapshot,
} from './dailyReviewFormat'

const props = defineProps({
  // 簽核列（POST 回應、單日明細的 review、已簽紀錄列皆同形）
  record: { type: Object, required: true },
  // 唯讀抽屜另有「簽核時／目前可查」對照表，不重複列計數
  showCounts: { type: Boolean, default: true },
})

const cutOffset = computed(() => offsetLabel(props.record.timezone, props.record.window_start || props.record.signed_at))
const snapshot = computed(() => parseSnapshot(props.record.snapshot_json) || {})

const countItems = computed(() => ({
  login: countText(snapshot.value.login_failures, snapshot.value.login_failures_source),
  alerts: countText(snapshot.value.alerts_total ?? snapshot.value.unreviewed_alerts, snapshot.value.alerts_source),
  high: countText(snapshot.value.high_risk_ops, snapshot.value.high_risk_ops_source),
}))

// 告警處置分布只有新制快照有；舊制快照只記未審閱數，照實說沒有分布
const dispositionText = computed(() => {
  const s = snapshot.value
  if (s.alerts_source === 'purged') return t('dailyReview.drawer.alerts.purgedShort')
  if (s.alerts_total === undefined) return t('dailyReview.drawer.record.dispositionLegacy')
  if (!s.alerts_total) return t('dailyReview.drawer.record.dispositionNone')
  return t('dailyReview.drawer.record.dispositionValue', {
    total: s.alerts_total,
    benign: s.alerts_benign ?? 0,
    escalated: s.alerts_escalated ?? 0,
  })
})
</script>

<style scoped>
.dr-record {
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-elevated);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}

.dr-record__head {
  display: flex;
  justify-content: space-between;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-sm);
}

.dr-record__title {
  font-weight: 600;
  color: var(--ot-text-primary);
}

.dr-record__fixed {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.dr-record__list {
  display: grid;
  grid-template-columns: 96px 1fr;
  gap: var(--ot-space-xs) var(--ot-space-md);
  margin: 0;
  font-size: var(--ot-font-size-sm);
}

.dr-record__list dt {
  color: var(--ot-text-secondary);
}

.dr-record__list dd {
  margin: 0;
  color: var(--ot-text-primary);
}

.dr-record__text {
  white-space: pre-wrap;
  word-break: break-word;
}

.dr-record__tag {
  margin-left: var(--ot-space-xs);
}

.dr-record__sub {
  margin-top: 2px;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}
</style>
