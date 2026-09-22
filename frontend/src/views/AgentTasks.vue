<template>
  <section class="agent-tasks">
    <PageHeader
      :title="t('agentTasks.title')"
      :description="t('agentTasks.listHelp')"
    />
    <el-form
      inline
      class="filter-bar"
      data-test="task-filters"
      @submit.prevent="search"
    >
      <el-form-item :label="t('agentTasks.subject')">
        <el-input-number
          v-model="filters.subject"
          :min="1"
          :precision="0"
        />
      </el-form-item>
      <el-form-item :label="t('agentPrincipals.owner')">
        <el-input-number
          v-model="filters.owner"
          :min="1"
          :precision="0"
        />
      </el-form-item>
      <el-form-item :label="t('agentTasks.timeRange')">
        <el-date-picker
          v-model="range"
          type="datetimerange"
        />
      </el-form-item>
      <el-form-item :label="t('agentTasks.reportStatus')">
        <el-select
          v-model="filters.report_status"
          clearable
          :placeholder="t('common.all')"
        >
          <el-option
            v-for="status in statuses"
            :key="status"
            :value="status"
            :label="t(`agentTasks.status.${status}`)"
          />
        </el-select>
      </el-form-item>
      <el-button
        type="primary"
        :loading="loading"
        @click="search"
      >
        {{ t('common.search') }}
      </el-button><el-button @click="reset">
        {{ t('common.reset') }}
      </el-button>
    </el-form>
    <el-alert
      v-if="error"
      :title="error"
      type="error"
      :closable="false"
    />
    <el-table
      v-loading="loading"
      :data="rows"
      stripe
      data-test="task-list"
    >
      <el-table-column :label="t('multiRequest.task')">
        <template #default="{ row }">
          <a :href="`/audit/agent-tasks/${row.id}`">#{{ row.id }}</a>
        </template>
      </el-table-column>
      <el-table-column :label="t('agentTasks.subject')">
        <template #default="{ row }">
          {{ row.username }} <PrincipalBadge
            kind="agent"
            :owner-id="row.owner_user_id"
          />
        </template>
      </el-table-column>
      <el-table-column :label="t('common.status')">
        <template #default="{ row }">
          {{ stateLabel(row.status) }}
        </template>
      </el-table-column>
      <el-table-column :label="t('agentTasks.reportStatus')">
        <template #default="{ row }">
          {{ statuses.includes(row.report_status) ? t(`agentTasks.status.${row.report_status}`) : t('agentSession.unknown') }}
        </template>
      </el-table-column>
      <el-table-column :label="t('agentTasks.created')">
        <template #default="{ row }">
          {{ formatDateTime(row.created_at) }}
        </template>
      </el-table-column>
      <el-table-column :label="t('agentTasks.closed')">
        <template #default="{ row }">
          {{ row.closed_at ? formatDateTime(row.closed_at) : t('agentTasks.open') }}
        </template>
      </el-table-column>
    </el-table>
    <el-pagination
      v-if="total"
      :current-page="page"
      :page-size="20"
      :total="total"
      layout="prev, pager, next, total"
      @current-change="changePage"
    />
  </section>
</template>
<script setup>
import { ref, reactive, watch, onBeforeUnmount } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { t } from '@/i18n'
import { getAgentTasks } from '@/api/agentTasks'
import { resolveApiError } from '@/api/error'
import { formatDateTime } from '@/utils/format'
import PageHeader from '@/components/PageHeader.vue'
import PrincipalBadge from '@/components/agent/PrincipalBadge.vue'
const route = useRoute(), router = useRouter()
const filters = reactive({ subject: undefined, owner: undefined, report_status: '' }), range = ref(null)
const rows = ref([]), total = ref(0), page = ref(1), loading = ref(false), error = ref('')
const statuses = ['submitted', 'missing', 'not_submitted']
const stateLabel = status => ['pending', 'approved', 'rejected', 'revoked', 'cancelled', 'expired'].includes(status) ? t(`multiRequest.state.${status}`) : t('agentSession.unknown')
let epoch = 0
async function load() {
  const version = ++epoch; loading.value = true; error.value = ''; rows.value = []; total.value = 0
  const params = { offset: (page.value - 1) * 20, limit: 20 }
  for (const key of ['subject', 'owner', 'report_status']) if (filters[key]) params[key] = filters[key]
  if (range.value?.length === 2) { params.from = new Date(range.value[0]).toISOString(); params.to = new Date(range.value[1]).toISOString() }
  try { const response = await getAgentTasks(params); if (version === epoch) { rows.value = response.data || []; total.value = response.total || 0 } }
  catch (e) { if (version === epoch) error.value = resolveApiError(e?.response?.data, e?.response?.status) }
  finally { if (version === epoch) loading.value = false }
}
function search() { page.value = 1; const query = {}; for (const key of ['subject', 'owner', 'report_status']) if (filters[key]) query[key] = String(filters[key]); if (range.value?.length === 2) { query.from = new Date(range.value[0]).toISOString(); query.to = new Date(range.value[1]).toISOString() } if (JSON.stringify(query) === JSON.stringify(route.query)) load(); else router.replace({ query }) }
function reset() { filters.subject = undefined; filters.owner = undefined; filters.report_status = ''; range.value = null; search() }
function changePage(value) { page.value = value; load() }
watch(() => route.query, query => { filters.subject = Number(query.subject) || undefined; filters.owner = Number(query.owner) || undefined; filters.report_status = statuses.includes(query.report_status) ? query.report_status : ''; range.value = query.from && query.to && Number.isFinite(Date.parse(query.from)) && Number.isFinite(Date.parse(query.to)) ? [new Date(query.from), new Date(query.to)] : null; page.value = 1; load() }, { immediate: true })
onBeforeUnmount(() => { epoch++ })
</script>
<style scoped>
.agent-tasks { color: var(--ot-text-primary); }
a { color: var(--ot-primary); }
.filter-bar { margin: var(--ot-space-lg) 0; padding: var(--ot-space-md); border: 1px solid var(--ot-border-subtle); border-radius: var(--ot-radius-lg); }
</style>
