<template>
  <section
    class="tool-ledger"
    data-test="tool-ledger"
  >
    <h2>{{ t('agentLedger.title') }}</h2>
    <p data-test="ledger-boundary">
      {{ t('agentLedger.boundary') }}
    </p>
    <el-form
      inline
      @submit.prevent="load"
    >
      <el-form-item :label="t('agentLedger.decision')">
        <el-select
          v-model="decision"
          clearable
          :placeholder="t('common.all')"
          @change="resetPage"
        >
          <el-option
            v-for="value in decisions"
            :key="value"
            :value="value"
            :label="t(`agentLedger.decisions.${value}`)"
          />
        </el-select>
      </el-form-item>
      <el-button
        :loading="loading"
        @click="load"
      >
        {{ t('common.refresh') }}
      </el-button>
    </el-form>
    <el-alert
      v-if="error"
      :title="t('agentLedger.loadFailed')"
      :description="error"
      type="error"
      :closable="false"
    />
    <p v-if="!loading && !error && !rows.length">
      {{ t('agentLedger.empty') }}
    </p>
    <div
      v-loading="loading"
      :aria-busy="loading"
    >
      <article
        v-for="row in rows"
        :key="row.id"
        class="tool-ledger__row"
        data-test="ledger-row"
      >
        <div class="tool-ledger__summary">
          <span>#{{ row.seq }}</span><time>{{ formatDateTime(row.created_at) }}</time><strong data-test="tool-action">{{ toolLabel(row.tool) }}</strong>
          <el-tag
            :type="row.decision === 'denied' || row.decision === 'breaker' ? 'warning' : 'info'"
            data-test="ledger-decision"
          >
            {{ decisionLabel(row.decision) }}
          </el-tag>
          <el-tag
            v-if="row.masked_count > 0"
            type="warning"
            data-test="masked-count"
          >
            {{ t('agentLedger.masked', { n: row.masked_count }) }}
          </el-tag><span v-else>{{ t('agentLedger.masked', { n: 0 }) }}</span>
          <span>{{ t('agentLedger.duration', { n: row.duration_ms }) }}</span>
          <span v-if="showSession"><a
            v-if="row.session_id"
            :href="`/sessions/${row.session_id}`"
          >{{ t('agentLedger.session', { id: row.session_id }) }}</a><span v-else>{{ t('agentLedger.noSession') }}</span></span>
        </div>
        <p v-if="row.decision === 'pending'">
          {{ t('agentLedger.pendingBoundary') }}
        </p>
        <p
          v-if="row.denial_code"
          data-test="denial-explanation"
        >
          {{ denialLabel(row.denial_code) }}
        </p>
        <details>
          <summary>{{ t('agentLedger.details') }}</summary>
          <dl>
            <dt>{{ t('agentLedger.reasonCode') }}</dt><dd><code>{{ row.denial_code || '—' }}</code></dd>
            <dt>{{ t('agentLedger.toolName') }}</dt><dd><code>{{ row.tool }}</code></dd>
            <dt>{{ t('agentLedger.result') }}</dt><dd>{{ row.decision === 'pending' ? t('agentLedger.unknown') : row.result_status || t('agentLedger.unknown') }}</dd>
            <dt>{{ t('agentLedger.arguments') }}</dt><dd><pre>{{ JSON.stringify(row.args_redacted, null, 2) }}</pre></dd>
            <dt>{{ t('agentLedger.digest') }}</dt><dd><code>{{ row.result_digest || t('agentLedger.unavailable') }}</code></dd>
            <dt>{{ t('agentLedger.excerpt') }}</dt><dd>
              <p data-test="excerpt-boundary">
                {{ t('agentLedger.excerptBoundary') }}
              </p><pre>{{ row.result_excerpt || t('agentLedger.unavailable') }}</pre>
            </dd>
          </dl>
        </details>
      </article>
    </div>
    <el-pagination
      v-if="total"
      :current-page="page"
      :page-size="pageSize"
      :total="total"
      layout="prev, pager, next, total"
      @current-change="changePage"
    />
  </section>
</template>
<script setup>
import { ref, watch, onBeforeUnmount } from 'vue'
import i18n, { t } from '@/i18n'
import { resolveApiError } from '@/api/error'
import { formatDateTime } from '@/utils/format'
import { getAgentToolCalls } from '@/api/agentTasks'
const props = defineProps({ query: { type: Object, default: () => ({}) }, showSession: { type: Boolean, default: true } })
const rows = ref([]), total = ref(0), page = ref(1), loading = ref(false), error = ref(''), decision = ref('')
const pageSize = 20
const decisions = ['pending', 'allowed', 'denied', 'breaker', 'rate_limited']
const allowedQuery = ['user_id', 'access_request_id', 'session_id', 'from', 'to']
let epoch = 0
const decisionLabel = value => decisions.includes(value) ? t(`agentLedger.decisions.${value}`) : t('agentLedger.unknown')
const toolLabel = tool => Object.prototype.hasOwnProperty.call(i18n.global.getLocaleMessage(i18n.global.locale.value).agentLedger.tools, tool) ? t(`agentLedger.tools.${tool}`) : t('agentLedger.unknownTool')
const denialLabel = code => resolveApiError({ code }, 403, t('agentLedger.unknownReason'))
async function load() {
  const version = ++epoch
  loading.value = true; error.value = ''; rows.value = []; total.value = 0
  if (Object.keys(props.query).some(key => ![...allowedQuery, 'decision'].includes(key))) { error.value = t('agentLedger.unsupportedQuery'); loading.value = false; return }
  const params = { offset: (page.value - 1) * pageSize, limit: pageSize }
  for (const key of allowedQuery) if (props.query[key] !== undefined && props.query[key] !== '') params[key] = props.query[key]
  if (decision.value) params.decision = decision.value
  try { const response = await getAgentToolCalls(params); if (version === epoch) { rows.value = response.data || []; total.value = response.total || 0 } }
  catch (e) { if (version === epoch) error.value = resolveApiError(e?.response?.data, e?.response?.status) }
  finally { if (version === epoch) loading.value = false }
}
function resetPage() { page.value = 1; load() }
function changePage(value) { page.value = value; load() }
watch(() => props.query, () => { decision.value = props.query.decision || ''; resetPage() }, { deep: true, immediate: true })
onBeforeUnmount(() => { epoch++ })
</script>
<style scoped>
.tool-ledger { color: var(--ot-text-primary); }
h2 { font-size: var(--ot-font-size-lg); }
.tool-ledger__row { border: 1px solid var(--ot-border-subtle); border-radius: var(--ot-radius-md); padding: var(--ot-space-md); margin: var(--ot-space-md) 0; }
.tool-ledger__summary { display: flex; flex-wrap: wrap; gap: var(--ot-space-sm); align-items: center; }
p, dt { color: var(--ot-text-secondary); font-size: var(--ot-font-size-sm); }
dl { display: grid; grid-template-columns: auto minmax(0, 1fr); gap: var(--ot-space-sm) var(--ot-space-md); }
dd { margin: 0; overflow-wrap: anywhere; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; font-family: var(--ot-font-mono); font-size: var(--ot-font-size-sm); }
a { color: var(--ot-primary); }
summary { cursor: pointer; margin-top: var(--ot-space-sm); }
</style>
