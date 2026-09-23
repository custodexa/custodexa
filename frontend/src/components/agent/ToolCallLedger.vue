<template>
  <section
    class="tool-ledger"
    data-test="tool-ledger"
  >
    <header class="ledger-head">
      <h2>{{ t('agentLedger.title') }}</h2>
      <p
        class="ledger-hint"
        data-test="ledger-boundary"
      >
        {{ t('agentLedger.boundary') }}
      </p>
    </header>
    <el-form
      inline
      @submit.prevent="load"
    >
      <el-form-item :label="t('agentLedger.decision')">
        <el-select
          v-model="decision"
          clearable
          :placeholder="t('common.all')"
          :aria-label="t('agentLedger.decision')"
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
    <EmptyState
      v-if="!loading && !error && !rows.length"
      :title="t('agentLedger.empty')"
      :hint="t('agentLedger.emptyNext')"
      :icon="ListChecks"
    />
    <div
      v-loading="loading"
      :aria-busy="loading"
    >
      <ToolCallLedgerTable
        v-if="rows.length"
        :rows="rows"
        :targets="targets"
        :link-mode="showSession ? 'session' : 'task'"
      />
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
import { t } from '@/i18n'
import { resolveApiError } from '@/api/error'
import { getAgentToolCalls } from '@/api/agentTasks'
import { ListChecks } from 'lucide-vue-next'
import EmptyState from '@/components/EmptyState.vue'
import ToolCallLedgerTable from '@/components/agent/ToolCallLedgerTable.vue'
const props = defineProps({ query: { type: Object, default: () => ({}) }, showSession: { type: Boolean, default: true }, targets: { type: Object, default: () => ({}) } })
const rows = ref([]), total = ref(0), page = ref(1), loading = ref(false), error = ref(''), decision = ref('')
const pageSize = 20
const decisions = ['pending', 'allowed', 'denied', 'breaker', 'rate_limited']
const allowedQuery = ['user_id', 'access_request_id', 'session_id', 'from', 'to']
let epoch = 0
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
/* 標題、說明句、篩選列三者原本讀起來同一階：標題加重、說明句降級，
   篩選列拉開間距才看得出「這是這一區塊的工具列」 */
.ledger-head { margin-bottom: var(--ot-space-md); }
h2 { font-size: var(--ot-font-size-lg); font-weight: 600; margin: 0; }
.ledger-hint { margin: var(--ot-space-xs) 0 0; color: var(--ot-text-secondary); font-size: var(--ot-font-size-sm); }
/* 判定篩選同樣會塌到 44px 而看不見佔位字，寬度下限與任務列表的篩選一致 */
.tool-ledger :deep(.el-select) { min-width: calc(var(--ot-space-xl) * 6); }
</style>
