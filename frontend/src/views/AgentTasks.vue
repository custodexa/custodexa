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
      <el-form-item :label="t('agentPrincipals.agent')">
        <el-select
          v-model="filters.subject"
          filterable
          clearable
          remote
          reserve-keyword
          :remote-method="query => searchPrincipals('agent', query)"
          :loading="principalLoading.agent"
          :placeholder="t('agentTasks.searchByName')"
          data-test="task-subject-filter"
          @visible-change="visible => visible && searchPrincipals('agent', '')"
        >
          <el-option
            v-for="option in principalOptions.agent"
            :key="option.id"
            :value="option.id"
            :label="option.username"
          />
        </el-select>
      </el-form-item>
      <el-form-item :label="t('agentPrincipals.owner')">
        <el-select
          v-model="filters.owner"
          filterable
          clearable
          remote
          reserve-keyword
          :remote-method="query => searchPrincipals('owner', query)"
          :loading="principalLoading.owner"
          :placeholder="t('agentTasks.searchByName')"
          data-test="task-owner-filter"
          @visible-change="visible => visible && searchPrincipals('owner', '')"
        >
          <el-option
            v-for="option in principalOptions.owner"
            :key="option.id"
            :value="option.id"
            :label="option.username"
          />
        </el-select>
      </el-form-item>
      <el-form-item :label="t('agentTasks.timeRange')">
        <el-date-picker
          v-model="range"
          type="datetimerange"
          :start-placeholder="t('agentTasks.created')"
          :end-placeholder="t('agentTasks.closed')"
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
          <a :href="`/audit/agent-tasks/${row.id}`">{{ t('agentTasks.detailTitle', { id: row.id }) }}</a>
        </template>
      </el-table-column>
      <el-table-column
        :label="t('agentPrincipals.agent')"
        min-width="170"
      >
        <template #default="{ row }">
          <span class="subject-name">{{ row.username }}</span> <PrincipalBadge
            kind="agent"
            :owner-id="row.owner_user_id"
            :owner-name="row.owner_username"
          />
        </template>
      </el-table-column>
      <!-- 代表人：契約已投影 on_behalf_of_username，列表沒有這欄就答不出「替誰做」 -->
      <el-table-column
        :label="t('agentSession.onBehalf')"
        min-width="150"
        show-overflow-tooltip
      >
        <template #default="{ row }">
          <span data-test="task-on-behalf">{{ onBehalfText(row) }}</span>
        </template>
      </el-table-column>
      <el-table-column :label="t('agentTasks.reason')">
        <template #default="{ row }">
          {{ row.reason }}
        </template>
      </el-table-column>
      <el-table-column :label="t('common.status')">
        <template #default="{ row }">
          <el-tag :type="statusTagType(row.status)">
            {{ stateLabel(row.status) }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column
        :label="t('agentTasks.reportStatus')"
        min-width="150"
      >
        <template #default="{ row }">
          <!-- 已關閉卻沒有報告是已定案的稽核缺口，不是待處置：用 danger 而非
               與「等候審核」同一支琥珀。未關閉而尚無報告不帶語意，走中性彩標 -->
          <el-tag
            class="status-tag"
            :class="{ 'ot-tag-neutral': row.report_status === 'not_submitted' }"
            :type="row.report_status === 'submitted' ? 'success' : row.report_status === 'missing' ? 'danger' : 'info'"
          >
            {{ statuses.includes(row.report_status) ? t(`agentTasks.status.${row.report_status}`) : t('agentSession.unknown') }}
          </el-tag>
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
      <template #empty>
        <EmptyState
          :title="t('agentTasks.emptyTitle')"
          :hint="t('agentTasks.emptyHint')"
        />
      </template>
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
import { getUserList, getUserDetail } from '@/api/user'
import { resolveApiError } from '@/api/error'
import { formatDateTime } from '@/utils/format'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import PrincipalBadge from '@/components/agent/PrincipalBadge.vue'
const route = useRoute(), router = useRouter()
const filters = reactive({ subject: undefined, owner: undefined, report_status: '' }), range = ref(null)
const rows = ref([]), total = ref(0), page = ref(1), loading = ref(false), error = ref('')
const statuses = ['submitted', 'missing', 'not_submitted']
// 名稱查詢：稽核者手上通常只有名字。送出仍是 id（契約只吃 id），
// 名稱解析走既有的 `GET /users?search=&kind=`，不新增後端端點。
const principalOptions = reactive({ agent: [], owner: [] })
const principalLoading = reactive({ agent: false, owner: false })
const PRINCIPAL_KIND = { agent: 'agent', owner: 'human' }
async function searchPrincipals(field, query) {
  principalLoading[field] = true
  try {
    const response = await getUserList({ include_agents: true, kind: PRINCIPAL_KIND[field], search: query || undefined, page: 1, page_size: 20 })
    principalOptions[field] = response?.data || []
  } catch { /* 查不到就維持現有選項；篩選是輔助入口，不把整頁卡在這裡 */ }
  finally { principalLoading[field] = false }
}
// 由網址帶 id 進來時補一筆選項，否則下拉只顯示數字
async function ensurePrincipalOption(field, id) {
  if (!id || principalOptions[field].some(option => option.id === id)) return
  try {
    const response = await getUserDetail(id)
    const user = response?.data || response
    if (user?.id) principalOptions[field] = [...principalOptions[field], user]
  } catch { /* 讀不到名稱時保留 id，不阻斷查詢 */ }
}
// 名稱沒投影就說「未提供」，不把 id 當名字顯示
const onBehalfText = row => row.on_behalf_of_username || (row.on_behalf_of_user_id ? t('agentPrincipals.unavailable') : t('agentSession.none'))
const stateLabel = status => ['pending', 'approved', 'rejected', 'revoked', 'cancelled', 'expired'].includes(status) ? t(`multiRequest.state.${status}`) : t('agentSession.unknown')
const statusTagType = status => status === 'approved' ? 'success' : status === 'pending' ? 'warning' : ['rejected', 'revoked'].includes(status) ? 'danger' : 'info'
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
watch(() => route.query, query => { filters.subject = Number(query.subject) || undefined; filters.owner = Number(query.owner) || undefined; ensurePrincipalOption('agent', filters.subject); ensurePrincipalOption('owner', filters.owner); filters.report_status = statuses.includes(query.report_status) ? query.report_status : ''; range.value = query.from && query.to && Number.isFinite(Date.parse(query.from)) && Number.isFinite(Date.parse(query.to)) ? [new Date(query.from), new Date(query.to)] : null; page.value = 1; load() }, { immediate: true })
onBeforeUnmount(() => { epoch++ })
</script>
<style scoped>
.agent-tasks { color: var(--ot-text-primary); }
/* 識別字不從中間切（demo-agent-35f3 → demo-agent-／35f3）：整詞換行 */
.agent-tasks :deep(.cell) { overflow-wrap: normal; word-break: normal; }
.subject-name { white-space: nowrap; }
a { color: var(--ot-primary); }
/* 三語的報告狀態標籤長短差一倍：固定單行會被欄界切掉，改為可折行 */
.status-tag { height: auto; white-space: normal; line-height: 1.5; padding-top: var(--ot-space-xs); padding-bottom: var(--ot-space-xs); }
.filter-bar { margin: var(--ot-space-lg) 0; padding: var(--ot-space-md); border: 1px solid var(--ot-border-subtle); border-radius: var(--ot-radius-lg); }
/* 下拉在 inline 表單裡沒有寬度依據時會塌到 44px，佔位字（「全部」）整個看不見。
   給一個與同列其他篩選一致的下限，寬度由間距階推導 */
.filter-bar :deep(.el-select) { min-width: calc(var(--ot-space-xl) * 6); }
</style>
