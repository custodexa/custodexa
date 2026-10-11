<template>
  <!-- 變更業務時區前的確認：說清楚哪一天起改用新時區、之前的日子不變。
       改回目前生效的時區而已有待生效變更時，改說「取消原訂的變更」 -->
  <el-dialog
    v-model="visible"
    :title="cancelsPending ? $t('dailyReview.timezone.confirm.cancelTitle') : $t('dailyReview.timezone.confirm.title')"
    width="520px"
    append-to-body
    data-test="dr-tz-confirm"
    @closed="settle(false)"
  >
    <template v-if="cancelsPending">
      <dl class="dr-tzc__rows">
        <dt>{{ $t('dailyReview.timezone.confirm.active') }}</dt>
        <dd>{{ withOffset(active) }}</dd>
        <dt>{{ $t('dailyReview.timezone.confirm.planned') }}</dt>
        <dd class="dr-tzc__struck">
          {{ $t('dailyReview.timezone.confirm.plannedValue', { date: pending.effective_date, tz: withOffset(pending.value) }) }}
        </dd>
        <dt>{{ $t('dailyReview.timezone.confirm.to') }}</dt>
        <dd class="dr-tzc__strong">
          {{ $t('dailyReview.timezone.confirm.keepValue', { tz: withOffset(active) }) }}
        </dd>
      </dl>
      <ul
        class="dr-tzc__list"
        data-test="dr-tz-confirm-body"
      >
        <li>{{ $t('dailyReview.timezone.confirm.cancelPlanned', { date: pending.effective_date, tz: pending.value, active }) }}</li>
        <li>{{ $t('dailyReview.timezone.confirm.cancelAll', { active }) }}</li>
        <li>{{ $t('dailyReview.timezone.confirm.cancelRecords') }}</li>
      </ul>
    </template>
    <template v-else>
      <dl class="dr-tzc__rows">
        <dt>{{ $t('dailyReview.timezone.confirm.current') }}</dt>
        <dd>{{ withOffset(active) }}</dd>
        <dt>{{ $t('dailyReview.timezone.confirm.to') }}</dt>
        <dd class="dr-tzc__strong">
          {{ withOffset(to) }}
        </dd>
      </dl>
      <ul
        class="dr-tzc__list"
        data-test="dr-tz-confirm-body"
      >
        <li v-if="effectiveDate">
          {{ $t('dailyReview.timezone.confirm.fromDay', { date: effectiveDate, tz: to }) }}
        </li>
        <li v-if="today">
          {{ $t('dailyReview.timezone.confirm.keep', { today, offset: offsetLabel(active) }) }}
        </li>
        <li>{{ $t('dailyReview.timezone.confirm.deadline', { tz: to }) }}</li>
      </ul>
    </template>
    <p class="dr-tzc__audit">
      {{ $t('dailyReview.timezone.confirm.audit') }}
    </p>
    <template #footer>
      <el-button
        data-test="dr-tz-confirm-cancel"
        @click="settle(false)"
      >
        {{ cancelsPending ? $t('dailyReview.timezone.confirm.cancelNo') : $t('common.cancel') }}
      </el-button>
      <el-button
        type="primary"
        data-test="dr-tz-confirm-ok"
        @click="settle(true)"
      >
        {{ cancelsPending
          ? $t('dailyReview.timezone.confirm.cancelOk', { tz: active })
          : $t('dailyReview.timezone.confirm.ok') }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { computed, ref } from 'vue'
import { addDays, offsetLabel, zoneOffsetLabel } from './dailyReviewFormat'

const visible = ref(false)
const from = ref('')
const to = ref('')
const tzState = ref(null)
let resolver = null

// 目前生效的時區以後端為準；讀不到時退回政策列的舊值
const active = computed(() => tzState.value?.active || from.value)
const pending = computed(() => tzState.value?.pending || null)
const today = computed(() => tzState.value?.today?.date || '')
const effectiveDate = computed(() => (today.value ? addDays(today.value, 1) : ''))
const cancelsPending = computed(() => Boolean(pending.value) && to.value === active.value)

const withOffset = (tz) => (tz ? `${tz}（${zoneOffsetLabel(tz)}）` : '')

function settle(ok) {
  if (!resolver) return
  const resolve = resolver
  resolver = null
  visible.value = false
  resolve(ok)
}

/**
 * 開啟確認框；回傳 Promise<boolean>（true＝確認變更）
 * @param {{ from: string, to: string, state: object|null }} args
 */
function ask(args) {
  from.value = args.from
  to.value = args.to
  tzState.value = args.state || null
  visible.value = true
  return new Promise((resolve) => {
    resolver = resolve
  })
}

defineExpose({ ask })
</script>

<style scoped>
.dr-tzc__rows {
  display: grid;
  grid-template-columns: 96px 1fr;
  gap: var(--ot-space-xs) var(--ot-space-md);
  margin: 0 0 var(--ot-space-md);
}

.dr-tzc__rows dt {
  color: var(--ot-text-secondary);
}

.dr-tzc__rows dd {
  margin: 0;
  color: var(--ot-text-primary);
}

.dr-tzc__strong {
  font-weight: 600;
}

.dr-tzc__struck {
  text-decoration: line-through;
  color: var(--ot-text-secondary) !important;
}

.dr-tzc__list {
  margin: 0;
  padding-left: var(--ot-space-lg);
  line-height: 1.7;
  color: var(--ot-text-primary);
}

.dr-tzc__audit {
  margin: var(--ot-space-md) 0 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}
</style>
