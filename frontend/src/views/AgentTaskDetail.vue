<template>
  <section class="task-detail">
    <PageHeader :title="t('agentTasks.detailTitle', { id: taskId })">
      <template #actions>
        <a href="/audit/agent-tasks">{{ t('agentTasks.back') }}</a><el-button
          :loading="loading"
          @click="load"
        >
          {{ t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>
    <el-alert
      v-if="error"
      :title="error"
      type="error"
      :closable="false"
    />
    <div
      v-if="task"
      v-loading="loading"
      class="task-sections"
    >
      <section data-test="task-who">
        <h2>{{ t('agentTasks.sections.who') }}</h2>
        <p>
          {{ task.executor?.username || `#${task.executor_user_id || task.requester_id}` }} <PrincipalBadge
            :kind="task.executor?.kind || ''"
            :owner-id="task.executor?.owner_user_id"
            :owner-name="task.executor?.owner_username"
          />
        </p>
        <p>{{ t('agentTasks.currentOwner') }}</p>
        <dl><dt>{{ t('agentSession.onBehalf') }}</dt><dd>{{ task.requester_id === (task.executor_user_id || task.requester_id) ? t('agentSession.none') : (task.requester?.username || `#${task.requester_id}`) }}</dd><dt>{{ t('common.requestReason') }}</dt><dd>{{ task.reason }}</dd><dt>{{ t('agentTasks.created') }}</dt><dd>{{ formatDateTime(task.created_at) }}</dd></dl>
        <a :href="`/audit/workbench?subject=user&id=${task.executor_user_id || task.requester_id}`">{{ t('menu.auditWorkbench') }}</a>
      </section>
      <section data-test="task-grants">
        <h2>{{ t('agentTasks.sections.grants') }}</h2>
        <table
          class="grants-table"
          data-test="grants-table"
        >
          <thead><tr><th>{{ t('common.asset') }}</th><th>{{ t('multiRequest.accounts') }}</th><th>{{ t('common.status') }}</th><th>{{ t('agentTasks.approvedWindow') }}</th><th>{{ t('agentTasks.decider') }}</th></tr></thead>
          <tbody>
            <tr
              v-for="item in task.items || []"
              :key="item.id"
            >
              <td>{{ assetLabels[item.asset_id]?.name || t('common.assetRef', { id: item.asset_id }) }}<p>{{ t('multiRequest.itemId', { id: item.id }) }}</p></td>
              <td>{{ item.accounts?.length ? item.accounts.join(t('common.listSeparator')) : t('multiRequest.allAccounts') }}</td>
              <td>
                {{ stateLabel(item.status) }}<p v-if="item.approved_duration_minutes != null && item.approved_duration_minutes < task.requested_duration_minutes">
                  {{ t('agentTasks.reduced') }}
                </p><p v-if="item.revoked_at">
                  {{ t('multiRequest.revokedAt', { time: formatDateTime(item.revoked_at) }) }} · {{ item.revoke_note }}
                </p>
              </td>
              <td>
                <template v-if="item.approved_date_start">
                  {{ formatDateTime(item.approved_date_start) }} — {{ approvedEnd(item) }}
                </template><span v-else>{{ t('agentSession.unknown') }}</span><p>{{ t('common.minutesN', { n: item.approved_duration_minutes ?? task.requested_duration_minutes }) }}</p>
              </td>
              <td>{{ item.decided_by ? `#${item.decided_by}` : t('agentSession.unknown') }}<p>{{ item.decided_at ? formatDateTime(item.decided_at) : t('agentSession.unknown') }}</p></td>
            </tr>
          </tbody>
        </table>
        <p
          v-if="task.decision_note"
          data-test="approval-note"
        >
          {{ task.decision_note }}
        </p>
        <p
          v-for="approval in task.approvals || []"
          :key="approval.id"
          data-test="approval-note"
        >
          #{{ approval.approver_id }} · {{ formatDateTime(approval.created_at) }} · {{ approval.note }}
        </p>
        <el-pagination
          v-if="approvalTotal > 20"
          :current-page="approvalPage"
          :page-size="20"
          :total="approvalTotal"
          layout="prev, pager, next, total"
          @current-change="changeApprovals"
        />
      </section>
      <section data-test="task-activity">
        <h2>{{ t('agentTasks.sections.activity') }}</h2>
        <el-alert
          v-if="sessionError"
          :title="sessionError"
          type="error"
          :closable="false"
        />
        <p v-if="!sessionError && !sessions.length">
          {{ t('agentTasks.noSessions') }}
        </p>
        <article
          v-for="session in sessions"
          :key="session.id"
          class="task-item"
          data-test="task-session"
        >
          <a :href="`/sessions/${session.id}`">{{ t('agentLedger.session', { id: session.id }) }}</a> · {{ formatDateTime(session.start_time) }}
          <p>{{ t('agentSession.owner') }}: {{ session.owner_user_id ? `#${session.owner_user_id}` : t('agentSession.unknown') }} · {{ t('agentSession.token') }}: {{ session.agent_token_name || t('agentSession.unknown') }}</p>
          <a
            v-if="session.has_recording"
            :href="`/sessions/${session.id}#recording`"
          >{{ t('agentTasks.recording') }}</a>
        </article>
        <el-pagination
          v-if="sessionTotal"
          :current-page="sessionPage"
          :page-size="20"
          :total="sessionTotal"
          layout="prev, pager, next, total"
          @current-change="changeSessions"
        />
        <ToolCallLedger
          :key="taskId"
          :query="{ access_request_id: taskId }"
        />
      </section>
      <section data-test="task-reports">
        <h2>{{ t('agentTasks.sections.reports') }}</h2>
        <p data-test="report-boundary">
          {{ t('agentTasks.selfReport') }}
        </p>
        <p
          v-if="reports.missing_report_at_close"
          data-test="missing-report"
        >
          {{ t('agentTasks.missingAtClose', { time: formatDateTime(reports.closed_at) }) }}
        </p>
        <p v-if="!reports.total">
          {{ t('agentTasks.noReports') }}
        </p>
        <article
          v-for="report in visibleReports"
          :key="report.id"
          data-test="report-version"
        >
          <h3>{{ t('agentTasks.version', { n: report.version, time: formatDateTime(report.submitted_at) }) }}<span v-if="reports.closed_at && Date.parse(report.submitted_at) > Date.parse(reports.closed_at)"> · {{ t('agentTasks.revision') }}</span></h3>
          <pre>{{ report.body }}</pre>
        </article>
        <el-button
          v-if="reports.total > 1"
          data-test="toggle-reports"
          @click="showVersions = !showVersions"
        >
          {{ t(showVersions ? 'agentTasks.latestOnly' : 'agentTasks.allVersions') }}
        </el-button>
        <el-pagination
          v-if="showVersions && reports.total > 20"
          :current-page="reportPage"
          :page-size="20"
          :total="reports.total"
          layout="prev, pager, next, total"
          @current-change="changeReports"
        />
      </section>
    </div>
  </section>
</template>
<script setup>
import { computed, ref, watch, onBeforeUnmount } from 'vue'
import { useRoute } from 'vue-router'
import { t } from '@/i18n'
import { getAgentTask } from '@/api/agentTasks'
import { getSessionList } from '@/api/sessions'
import { resolveApiError } from '@/api/error'
import { formatDateTime } from '@/utils/format'
import { useAssetLabels } from '@/composables/useAssetLabels'
import PageHeader from '@/components/PageHeader.vue'
import PrincipalBadge from '@/components/agent/PrincipalBadge.vue'
import ToolCallLedger from '@/components/agent/ToolCallLedger.vue'
const route = useRoute(), taskId = computed(() => Number(route.params.requestId))
const approvalPage = ref(1), approvalTotal = ref(0)
const task = ref(null), reports = ref({ versions: [], total: 0 }), latest = ref(null), sessions = ref([]), sessionTotal = ref(0), sessionPage = ref(1), reportPage = ref(1), showVersions = ref(false), error = ref(''), sessionError = ref(''), loading = ref(false)
const assetLabels = useAssetLabels(() => (task.value?.items || []).map(item => ({ id: item.asset_id, name: item.asset?.name || (task.value.asset_id === item.asset_id ? task.value.asset?.name : '') })))
function approvedEnd(item) {
  const start = Date.parse(item.approved_date_start)
  return Number.isFinite(start) && item.approved_duration_minutes != null ? formatDateTime(new Date(start + item.approved_duration_minutes * 60000)) : t('agentSession.unknown')
}
const visibleReports = computed(() => showVersions.value ? reports.value.versions : latest.value ? [latest.value] : [])
const stateLabel = status => ['pending', 'approved', 'rejected', 'revoked', 'cancelled', 'expired'].includes(status) ? t(`multiRequest.state.${status}`) : t('agentSession.unknown')
let epoch = 0, sessionEpoch = 0, reportEpoch = 0, approvalEpoch = 0
async function loadSessions() {
  const version = ++sessionEpoch; sessionError.value = ''; sessions.value = []
  try { const response = await getSessionList({ access_request_id: taskId.value, page: sessionPage.value, page_size: 20 }); if (version === sessionEpoch) { sessions.value = response.data || []; sessionTotal.value = response.total || 0 } }
  catch (e) { if (version === sessionEpoch) sessionError.value = resolveApiError(e?.response?.data, e?.response?.status) }
}
async function load() {
  const version = ++epoch; sessionEpoch++; reportEpoch++; approvalEpoch++; approvalPage.value = 1; task.value = null; error.value = ''; loading.value = true; showVersions.value = false; sessionPage.value = 1; reportPage.value = 1
  try {
    const response = await getAgentTask(taskId.value, { limit: 20, offset: 0 })
    if (version !== epoch) return
    task.value = response.request; approvalTotal.value = response.approval_total || 0; reports.value = response.reports; latest.value = response.reports.versions[0] || null
    await loadSessions()
  } catch (e) { if (version === epoch) error.value = resolveApiError(e?.response?.data, e?.response?.status) }
  finally { if (version === epoch) loading.value = false }
}
async function changeApprovals(page) {
  const version = ++approvalEpoch
  try { const response = await getAgentTask(taskId.value, { limit: 20, approval_offset: (page - 1) * 20 }); if (version === approvalEpoch) { task.value.approvals = response.request.approvals; approvalPage.value = page } }
  catch (e) { if (version === approvalEpoch) error.value = resolveApiError(e?.response?.data, e?.response?.status) }
}
function changeSessions(page) { sessionPage.value = page; loadSessions() }
async function changeReports(page) {
  const version = ++reportEpoch
  try { const response = await getAgentTask(taskId.value, { limit: 20, offset: (page - 1) * 20 }); if (version === reportEpoch) { reports.value = response.reports; reportPage.value = page } }
  catch (e) { if (version === reportEpoch) error.value = resolveApiError(e?.response?.data, e?.response?.status) }
}
watch(taskId, load, { immediate: true })
onBeforeUnmount(() => { epoch++; sessionEpoch++; reportEpoch++; approvalEpoch++ })
</script>
<style scoped>
.task-detail { color: var(--ot-text-primary); }
.task-sections > section { padding: var(--ot-space-lg); margin-top: var(--ot-space-lg); background: var(--ot-bg-surface); border: 1px solid var(--ot-border-subtle); border-radius: var(--ot-radius-lg); }
h2 { font-size: var(--ot-font-size-xl); } h3 { font-size: var(--ot-font-size-lg); }
p, dt { color: var(--ot-text-secondary); } a { color: var(--ot-primary); }
dl { display: grid; grid-template-columns: auto minmax(0, 1fr); gap: var(--ot-space-sm) var(--ot-space-md); } dd { margin: 0; }
.grants-table { width: 100%; table-layout: fixed; border-collapse: collapse; }
.grants-table th, .grants-table td { padding: var(--ot-space-sm); text-align: start; vertical-align: top; overflow-wrap: anywhere; border-bottom: 1px solid var(--ot-border-subtle); }
.grants-table p { font-size: var(--ot-font-size-sm); }
pre { white-space: pre-wrap; overflow-wrap: anywhere; font-family: var(--ot-font-mono); font-size: var(--ot-font-size-sm); }
</style>
