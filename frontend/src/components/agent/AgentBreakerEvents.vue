<template>
  <section
    class="breaker-events"
    data-test="breaker-events"
  >
    <h3>{{ t('agentBreaker.events') }}</h3>
    <p>{{ t('agentBreaker.assetNameBoundary') }}</p>
    <p>{{ t('agentBreaker.countBoundary', { n: thresholdCount }) }}</p>
    <el-alert
      v-if="error"
      :title="error"
      type="error"
      :closable="false"
    />
    <p v-if="!loading && !error && !rows.length">
      {{ t('agentBreaker.noEvents') }}
    </p>
    <article
      v-for="event in rows"
      :key="event.id"
      data-test="probe-event"
    >
      <div data-test="probe-target">
        <time>{{ formatDateTime(event.created_at) }}</time> · {{ assetLabels[event.asset_ref]?.name || t('common.assetRef', { id: event.asset_ref }) }}<span v-if="assetLabels[event.asset_ref]?.protocol"> · {{ assetLabels[event.asset_ref].protocol.toUpperCase() }}</span>
      </div>
      <details><summary>{{ t('agentLedger.details') }}</summary><p>{{ t('common.assetRef', { id: event.asset_ref }) }} · {{ event.endpoint }}</p></details>
      <p>{{ ['never_visible', 'revoked', 'retired'].includes(event.class) ? t(`agentBreaker.classes.${event.class}`) : t('agentSession.unknown') }}</p>
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
      <h3>{{ t('agentPrincipals.issuedKeys') }}</h3><p>{{ t('agentBreaker.tokenBoundary') }}</p>
      <el-alert
        v-if="tokenError"
        :title="tokenError"
        type="error"
        :closable="false"
      />
      <p
        v-for="token in tokens"
        :key="token.id"
        data-test="breaker-token"
      >
        {{ token.name }} · #{{ token.id }}<span v-if="token.suspended_at && token.suspended_reason === 'agent_breaker_tripped'"> · {{ t('agentBreaker.tokenStopped', { time: formatDateTime(token.suspended_at) }) }}</span>
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
import { useAssetLabels } from '@/composables/useAssetLabels'
const props = defineProps({ userId: { type: Number, required: true }, readTokens: Boolean })
const emit = defineEmits(['state'])
const rows = ref([]), tokens = ref([]), total = ref(0), page = ref(1), loading = ref(false), error = ref(''), tokenError = ref('')
const assetLabels = useAssetLabels(() => rows.value.map(row => ({ id: row.asset_ref })))
const thresholdCount = computed(() => new Set(rows.value.filter(row => row.class === 'never_visible').map(row => row.asset_ref)).size)
let epoch = 0
async function load() {
  const version = ++epoch; loading.value = true; error.value = ''; rows.value = []
  try { const response = await getAgentBreakerEvents(props.userId, { offset: (page.value - 1) * 20, limit: 20 }); if (version === epoch) { rows.value = response.data || []; total.value = response.total || 0; emit('state', response.breaker_pending_at) } }
  catch (e) { if (version === epoch) error.value = resolveApiError(e?.response?.data, e?.response?.status) }
  finally { if (version === epoch) loading.value = false }
}
async function loadTokens() {
  tokens.value = []; tokenError.value = ''; const version = epoch
  if (!props.readTokens) return
  try { const response = await getAgentTokens(props.userId); if (version === epoch) tokens.value = response.data || [] }
  catch (e) { if (version === epoch) tokenError.value = resolveApiError(e?.response?.data, e?.response?.status) }
}
function changePage(value) { page.value = value; load() }
watch(() => props.userId, () => { page.value = 1; load(); loadTokens() }, { immediate: true })
onBeforeUnmount(() => { epoch++ })
</script>
<style scoped>
.breaker-events { padding: var(--ot-space-md); margin: var(--ot-space-md) 0; background: var(--ot-bg-surface); border: 1px solid var(--ot-border-subtle); border-radius: var(--ot-radius-lg); }
article { padding: var(--ot-space-sm) 0; border-bottom: 1px solid var(--ot-border-subtle); }
h3 { font-size: var(--ot-font-size-lg); } p { color: var(--ot-text-secondary); font-size: var(--ot-font-size-sm); }
</style>
