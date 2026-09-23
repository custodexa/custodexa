<template>
  <section
    class="breaker-events"
    data-test="breaker-events"
  >
    <h3>
      {{ t('agentBreaker.events') }} <HelpTip :content="t('agentBreaker.assetNameBoundary')" />
    </h3>
    <!-- 「不同目標數」是這一區塊唯一的統計，原本埋在說明句裡與本文同字級，
         讀者分不出哪個是數字。數字獨立、說明句只留一句 -->
    <StatBlock
      data-test="breaker-stats"
      :items="[{ value: thresholdCount, label: t('agentBreaker.statTargets'), dataTest: 'breaker-targets-stat' }]"
    />
    <p class="breaker-events__hint">
      {{ t('agentBreaker.countBoundaryShort') }}
    </p>
    <el-alert
      v-if="error"
      :title="error"
      type="error"
      :closable="false"
    />
    <EmptyState
      v-if="!loading && !error && !rows.length"
      :title="t('agentBreaker.noEvents')"
      :hint="t('agentBreaker.noEventsNext')"
      :icon="ShieldAlert"
    />
    <p
      v-if="loading"
      data-test="events-loading"
    >
      {{ t('common.loading') }}
    </p>
    <article
      v-for="event in rows"
      :key="event.id"
      data-test="probe-event"
    >
      <!-- 每筆事件的分類詞都一樣，時間與目標才是區辨這一筆的資訊：
           分類降為彩標，時間＋目標升為該列主標 -->
      <p
        class="breaker-events__target"
        data-test="probe-target"
      >
        <time>{{ formatDateTime(event.created_at) }}</time> · {{ assetText(event) }}<span v-if="assetLabels[event.asset_ref]?.protocol"> · {{ protocolKindText(assetLabels[event.asset_ref].protocol) }}</span>
      </p>
      <el-tag
        :type="isCurrentTrip(event) ? 'warning' : undefined"
        :class="{ 'ot-tag-neutral': !isCurrentTrip(event) }"
        data-test="probe-class"
      >
        {{ ['never_visible', 'revoked', 'retired'].includes(event.class) ? t(`agentBreaker.classes.${event.class}`) : t('agentSession.unknown') }}
      </el-tag>
      <details><summary>{{ t('agentLedger.details') }}</summary><p>{{ assetText(event) }} · {{ event.endpoint }}</p></details>
    </article>
    <el-pagination
      v-if="total"
      :current-page="page"
      :page-size="20"
      :total="total"
      layout="prev, pager, next, total"
      @current-change="changePage"
    />
    <template v-if="readTokens">
      <h3>
        {{ t('agentPrincipals.issuedKeys') }} <HelpTip :content="t('agentBreaker.tokenBoundary')" />
      </h3>
      <p
        v-if="tokenLoading"
        data-test="tokens-loading"
      >
        {{ t('common.loading') }}
      </p>
      <el-alert
        v-if="tokenError"
        :title="tokenError"
        type="error"
        :closable="false"
      />
      <StatBlock
        v-if="!tokenLoading && !tokenError && tokens.length"
        data-test="breaker-token-summary"
        :items="[
          { value: usableCount, label: t('agentPrincipals.statUsable'), dataTest: 'breaker-usable-stat' },
          { value: suspendedCount, label: t('agentPrincipals.statSuspended'), dataTest: 'breaker-suspended-stat' },
        ]"
      />
      <p
        v-for="token in tokens"
        :key="token.id"
        class="breaker-events__token"
        data-test="breaker-token"
      >
        {{ token.name }}<el-tag
          :type="agentTokenTagType(tokenState(token), breakerPending)"
          :class="agentTokenTagClass(tokenState(token), breakerPending)"
          data-test="breaker-token-state"
        >
          {{ tokenStateText(token) }}
        </el-tag>
      </p>
    </template>
  </section>
</template>
<script setup>
import { ref, computed, watch, onBeforeUnmount } from 'vue'
import { t } from '@/i18n'
import { getAgentBreakerEvents, getAgentTokens } from '@/api/agents'
import { resolveApiError } from '@/api/error'
import { formatDateTime } from '@/utils/format'
import { protocolKindText } from '@/utils/protocol'
import { ShieldAlert } from 'lucide-vue-next'
import { useAssetLabels } from '@/composables/useAssetLabels'
import { agentTokenState, agentTokenTagType, agentTokenTagClass } from '@/utils/agentTokenStatus'
import EmptyState from '@/components/EmptyState.vue'
import StatBlock from '@/components/StatBlock.vue'
import HelpTip from '@/components/HelpTip.vue'
const props = defineProps({ userId: { type: Number, required: true }, readTokens: Boolean })
const emit = defineEmits(['state'])
const rows = ref([]), tokens = ref([]), total = ref(0), page = ref(1), loading = ref(false), error = ref(''), tokenError = ref(''), tokenLoading = ref(false)
// 鑰匙狀態要完整：停用只是其中一種，撤銷與到期同樣要看得見，
// 停用還要說出已存的原因與時間。彩標映射與抽屜共用同一份
// （utils/agentTokenStatus）：同一把停用鑰匙在兩頁之間不得是兩種嚴重度
const breakerPendingAt = ref(null)
const breakerPending = computed(() => Boolean(breakerPendingAt.value))
// 琥珀＝目前待處置這次跳閘的事件；同時刻也計入，舊事件與已解除歷史為中性。
const isCurrentTrip = event => event.class === 'never_visible' && breakerPendingAt.value && new Date(event.created_at) >= new Date(breakerPendingAt.value)
const tokenState = token => agentTokenState(token)
const usableCount = computed(() => tokens.value.filter(token => tokenState(token) === 'valid').length)
const suspendedCount = computed(() => tokens.value.filter(token => tokenState(token) === 'suspended').length)
const suspendReason = token => ['agent_breaker_tripped'].includes(token.suspended_reason)
  ? t(`agentPrincipals.suspendedReasons.${token.suspended_reason}`)
  : t('agentPrincipals.suspendedReasons.unknown')
function tokenStateText(token) {
  const state = tokenState(token)
  if (state === 'suspended') return t('agentBreaker.tokenStopped', { reason: suspendReason(token), time: formatDateTime(token.suspended_at) })
  if (state === 'revoked') return t('agentBreaker.tokenRevoked', { time: formatDateTime(token.revoked_at) })
  if (state === 'expired') return t('agentBreaker.tokenExpired', { time: formatDateTime(token.expires_at) })
  return t('agentPrincipals.tokenStatus.valid')
}
// 名稱由事件列自帶；這支仍要查一次，因為協議欄只有資產本體有
const assetLabels = useAssetLabels(() => rows.value.map(row => ({ id: row.asset_ref })))
// 事件列自己帶名稱（含已移除的資產），比另外查一次可靠；都讀不到才退回編號
function assetText(event) {
  const name = event.asset_name || assetLabels.value[event.asset_ref]?.name
  if (!name) return t('common.assetRef', { id: event.asset_ref })
  return event.asset_deleted ? t('common.assetRemoved', { name }) : name
}
const thresholdCount = computed(() => new Set(rows.value.filter(row => row.class === 'never_visible').map(row => row.asset_ref)).size)
let epoch = 0
async function load() {
  const version = ++epoch; loading.value = true; error.value = ''; rows.value = []
  try { const response = await getAgentBreakerEvents(props.userId, { offset: (page.value - 1) * 20, limit: 20 }); if (version === epoch) { rows.value = response.data || []; total.value = response.total || 0; breakerPendingAt.value = response.breaker_pending_at || null; emit('state', response.breaker_pending_at) } }
  catch (e) { if (version === epoch) error.value = resolveApiError(e?.response?.data, e?.response?.status) }
  finally { if (version === epoch) loading.value = false }
}
async function loadTokens() {
  tokens.value = []; tokenError.value = ''; const version = epoch
  if (!props.readTokens) return
  tokenLoading.value = true
  try { const response = await getAgentTokens(props.userId); if (version === epoch) tokens.value = response.data || [] }
  catch (e) { if (version === epoch) tokenError.value = resolveApiError(e?.response?.data, e?.response?.status) }
  finally { if (version === epoch) tokenLoading.value = false }
}
function changePage(value) { page.value = value; load() }
watch(() => props.userId, () => { page.value = 1; load(); loadTokens() }, { immediate: true })
onBeforeUnmount(() => { epoch++ })
</script>
<style scoped>
.breaker-events { padding: var(--ot-space-md); margin: var(--ot-space-md) 0; background: var(--ot-bg-surface); border: 1px solid var(--ot-border-subtle); border-radius: var(--ot-radius-lg); }
article { padding: var(--ot-space-sm) 0; border-bottom: 1px solid var(--ot-border-subtle); }
h3 { font-size: var(--ot-font-size-lg); font-weight: 600; margin: 0 0 var(--ot-space-sm); }
/* 事件本文（時間、目標、判定）是要讀的證據，維持主文字色；只有說明句降階 */
p { color: var(--ot-text-primary); font-size: var(--ot-font-size-md); }
.breaker-events__hint { color: var(--ot-text-secondary); font-size: var(--ot-font-size-sm); }
.breaker-events__target { font-weight: 600; margin: 0 0 var(--ot-space-xs); }
.breaker-events :deep(.el-tag) { height: auto; white-space: normal; line-height: 1.5; padding-top: var(--ot-space-xs); padding-bottom: var(--ot-space-xs); }
details summary { color: var(--ot-text-secondary); font-size: var(--ot-font-size-sm); cursor: pointer; }
.breaker-events__token { display: flex; align-items: center; gap: var(--ot-space-sm); flex-wrap: wrap; color: var(--ot-text-primary); }
</style>
