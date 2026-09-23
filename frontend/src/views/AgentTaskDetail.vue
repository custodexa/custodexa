<template>
  <section class="task-detail">
    <PageHeader
      :title="taskTitle"
      :description="t('agentTasks.detailHelp')"
    >
      <template #actions>
        <el-tag
          v-if="task"
          :type="closedAt ? 'info' : 'success'"
          data-test="task-status"
        >
          {{ closedAt ? t('agentTasks.closedAt', { time: formatDateTime(closedAt) }) : t('agentTasks.open') }}
        </el-tag><a href="/audit/agent-tasks">{{ t('agentTasks.back') }}</a><el-button
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
    <!-- 首屏摘要：四個核心問題（做了什麼／哪裡被擋／誰負責／有沒有交報告）
         的答案原本分散在三段之後，1440×900 不捲動一個都看不到 -->
    <dl
      v-if="task"
      class="task-summary"
      data-test="task-summary"
    >
      <div>
        <dt>{{ t('agentTasks.summary.didWhat') }}</dt>
        <dd>
          {{ stats.loaded ? t('agentTasks.summary.callsValue', { n: totalCalls }) : statsFailed ? t('agentTasks.summary.unknown') : t('agentTasks.summary.counting') }}<el-button
            v-if="statsFailed"
            link
            data-test="stats-retry"
            @click="loadStats"
          >
            {{ t('common.retry') }}
          </el-button>
        </dd>
      </div>
      <div>
        <dt>{{ t('agentTasks.summary.blockedWhere') }}</dt>
        <dd :class="{ 'task-summary__flag': stats.loaded && stats.blocked }">
          {{ stats.loaded ? t('agentTasks.summary.blockedValue', { n: stats.blocked }) : statsFailed ? t('agentTasks.summary.unknown') : t('agentTasks.summary.counting') }}
        </dd>
      </div>
      <div>
        <dt>{{ t('agentTasks.summary.whoOwns') }}</dt>
        <dd>{{ ownerName }}</dd>
      </div>
      <div>
        <dt>{{ t('agentTasks.summary.report') }}</dt>
        <dd>{{ latest ? t('agentTasks.summary.reportSubmitted', { n: latest.version }) : t('agentTasks.summary.reportMissing') }}</dd>
      </div>
      <!-- 「申請的和核准的差在哪」：原本要捲到第二段逐項比較才看得到 -->
      <div>
        <dt>{{ t('agentTasks.summary.grantDiff') }}</dt>
        <dd data-test="summary-grant-diff">
          {{ !compareItems.length ? t('agentTasks.summary.grantDiffNone') : narrowedCount ? t('agentTasks.summary.grantDiffValue', { n: narrowedCount, total: compareItems.length }) : scopeUnknownCount ? t('agentTasks.summary.grantDiffScopeUnknown', { n: scopeUnknownCount }) : t('agentTasks.summary.grantDiffSame') }}
        </dd>
      </div>
    </dl>
    <div
      v-if="task"
      v-loading="loading"
      class="task-sections"
    >
      <section data-test="task-who">
        <header class="sect-head">
          <div>
            <h2>{{ t('agentTasks.sections.who') }}</h2>
            <p class="sect-hint">
              {{ t('agentTasks.sectionHints.who') }}
            </p>
          </div>
        </header>
        <dl>
          <dt>{{ t('agentTasks.requesterLabel') }}</dt><dd>{{ task.requester?.username || t('agentPrincipals.unavailable') }}</dd>
          <dt>{{ t('agentTasks.executorLabel') }} <HelpTip :content="t('agentTasks.currentOwner')" /></dt><dd class="exec-cell">
            {{ task.executor?.username || t('agentPrincipals.unavailable') }} <a
              v-if="executorId"
              :href="`/users?open=${executorId}`"
              data-test="executor-keys-link"
            >{{ t('agentPrincipals.openKeys') }}</a> <PrincipalBadge
              :kind="task.executor?.kind || ''"
              :owner-id="task.executor?.owner_user_id"
              :owner-name="task.executor?.owner_username"
            />
          </dd>
          <dt>{{ t('agentSession.onBehalf') }}</dt><dd>{{ task.requester_id === (executorId || task.requester_id) ? t('agentSession.none') : (task.requester?.username || t('agentPrincipals.unavailable')) }}</dd>
          <dt>{{ t('common.requestReason') }}</dt><dd>{{ task.reason }}</dd>
          <dt>
            {{ t('agentTasks.openedAndClosed') }} <HelpTip
              v-if="closedAt"
              :content="t('agentTasks.closedMeaning')"
            />
          </dt><dd>
            {{ closedAt ? t('agentTasks.openedClosedValue', { created: formatDateTime(task.created_at), closed: formatDateTime(closedAt) }) : t('agentTasks.openedOnlyValue', { created: formatDateTime(task.created_at) }) }}
          </dd>
        </dl>
        <a :href="`/audit/workbench?subject=user&id=${executorId || task.requester_id}`">{{ t('menu.auditWorkbench') }}</a>
      </section>
      <section data-test="task-grants">
        <header class="sect-head">
          <div>
            <h2>
              {{ t('agentTasks.sections.grants') }} <HelpTip :content="`${t('agentTasks.sectionHints.grants')}\n${t('agentTasks.compare.note')}`" />
            </h2>
          </div>
          <el-tag
            v-if="narrowedCount"
            type="info"
            data-test="narrowed-count"
          >
            {{ t('agentTasks.compare.narrowedCount', { n: narrowedCount, total: compareItems.length }) }}
          </el-tag>
        </header>
        <article
          v-for="entry in compareItems"
          :key="entry.item.id"
          class="cmp"
          data-test="grant-compare"
        >
          <header class="cmp-head">
            <span class="cmp-asset">{{ assetLabels[entry.item.asset_id]?.name || t('common.assetRef', { id: entry.item.asset_id }) }}</span>
            <el-tag
              :type="entry.headType"
              data-test="grant-status"
            >
              {{ entry.headLabel }}
            </el-tag>
          </header>
          <div class="cmp-body">
            <div class="cmp-col">
              <span class="cmp-col-h">{{ t('agentTasks.compare.requested') }}</span>
              <div class="cmp-row">
                <span class="cmp-key">{{ t('agentTasks.compare.accounts') }}</span><span
                  class="cmp-val"
                  data-test="requested-accounts"
                >{{ entry.requestedAccounts === null ? t('agentTasks.compare.requestedAccountsUnavailable') : scopeText(entry.requestedAccounts) }}</span>
              </div>
              <div class="cmp-row">
                <span class="cmp-key">{{ t('agentTasks.compare.duration') }}</span><span class="cmp-val">{{ t('common.minutesN', { n: entry.requestedMinutes }) }}</span>
              </div>
            </div>
            <div class="cmp-col">
              <span class="cmp-col-h">{{ t('agentTasks.compare.approved') }}</span>
              <div class="cmp-row">
                <span class="cmp-key">{{ t('agentTasks.compare.accounts') }}</span><span
                  class="cmp-val"
                  :class="{ 'cmp-val-cut': entry.accountsReduced }"
                  data-test="approved-accounts"
                >{{ entry.approved ? scopeText(entry.item.accounts) : t('agentTasks.compare.noApprovedAccounts') }}<el-tag
                  v-if="entry.accountsReduced"
                  type="info"
                >{{ t('agentTasks.compare.reduced') }}</el-tag></span>
              </div>
              <div class="cmp-row">
                <span class="cmp-key">{{ t('agentTasks.compare.duration') }}</span><span
                  class="cmp-val"
                  :class="{ 'cmp-val-cut': entry.durationReduced }"
                  data-test="approved-duration"
                >
                  <template v-if="entry.approved && entry.approvedMinutes != null">
                    {{ t('common.minutesN', { n: entry.approvedMinutes }) }}<el-tag
                      v-if="entry.durationReduced"
                      type="info"
                    >{{ t('agentTasks.compare.reduced') }}</el-tag><p v-if="entry.item.approved_date_start">
                      {{ formatDateTime(entry.item.approved_date_start) }} — {{ approvedEnd(entry.item) }}
                    </p><p v-if="entry.durationReduced">
                      {{ t('agentTasks.compare.shorterBy', { n: entry.requestedMinutes - entry.approvedMinutes }) }}
                    </p>
                  </template><template v-else>
                    {{ t('agentTasks.compare.noApprovedWindow') }}
                  </template>
                </span>
              </div>
              <div class="cmp-row">
                <span class="cmp-key">{{ t('agentTasks.decider') }}</span><span
                  class="cmp-val"
                  data-test="grant-decider"
                >{{ entry.item.decided_by_username || (isAutoApproved(entry.item) ? t('agentTasks.autoApproved') : t('agentSession.unknown')) }}<p v-if="entry.item.decided_at">
                  {{ formatDateTime(entry.item.decided_at) }}
                </p><p v-if="entry.item.revoked_at">
                  {{ t('multiRequest.revokedAt', { time: formatDateTime(entry.item.revoked_at) }) }} · {{ entry.item.revoke_note }}
                </p></span>
              </div>
            </div>
          </div>
        </article>
        <p
          v-if="task.decision_note"
          class="field-label"
        >
          {{ t('agentTasks.decisionNoteLabel') }}
        </p>
        <p
          v-if="task.decision_note"
          class="field-value"
          data-test="approval-note"
        >
          {{ decisionNoteText(task.decision_note) }}
        </p>
        <p
          v-for="approval in task.approvals || []"
          :key="approval.id"
          class="field-value"
          data-test="approval-note"
        >
          {{ approval.approver_username || t('agentSession.unknown') }} · {{ formatDateTime(approval.created_at) }} · {{ decisionNoteText(approval.note) }}
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
        <header class="sect-head">
          <div>
            <h2>
              {{ t('agentTasks.sections.activity') }} <HelpTip :content="t('agentTasks.sectionHints.activity')" />
            </h2>
          </div>
        </header>
        <div class="activity-cards">
          <div class="activity-card">
            <h3>{{ t('agentTasks.sessionsTitle', { n: sessionTotal }) }}</h3>
            <el-alert
              v-if="sessionError"
              :title="sessionError"
              type="error"
              :closable="false"
            />
            <EmptyState
              v-if="!sessionError && !sessions.length"
              :title="t('agentTasks.noSessions')"
              :hint="t('agentTasks.noSessionsNext')"
              :icon="PlugZap"
            >
              <template #action>
                <a href="/sessions">{{ t('menu.sessions') }}</a>
              </template>
            </EmptyState>
            <article
              v-for="session in sessions"
              :key="session.id"
              class="task-item"
              data-test="task-session"
            >
              <div class="session-line">
                <a :href="`/sessions/${session.id}`">{{ t('agentLedger.session', { id: session.id }) }}</a><span class="session-asset">{{ session.asset?.name || t('common.assetRef', { id: session.asset_id }) }}</span><el-tag
                  :type="session.revoked_during_session_at ? 'danger' : sessionEnded(session) ? 'info' : 'success'"
                  data-test="session-status"
                >
                  {{ session.revoked_during_session_at ? getEndReasonText('revoked') : sessionEnded(session) ? t('common.stateEnded') : t('common.stateActive') }}
                </el-tag>
              </div>
              <p>{{ formatDateTime(session.start_time || session.created_at) }} · {{ t('sessionDetail.account') }}: {{ session.account_username || t('agentSession.unknown') }} · {{ t('agentSession.owner') }}: {{ session.owner_username || t('agentSession.unknown') }} · {{ t('agentSession.key') }}: {{ session.agent_token_name || t('agentSession.unknown') }}</p>
              <a
                v-if="session.has_recording"
                :href="`/sessions/${session.id}#recording`"
              >{{ t('agentTasks.recording') }}</a>
            </article>
            <el-pagination
              v-if="sessionTotal > 20"
              :current-page="sessionPage"
              :page-size="20"
              :total="sessionTotal"
              layout="prev, pager, next, total"
              @current-change="changeSessions"
            />
          </div>
          <div
            v-if="stats.loaded"
            class="activity-card"
            data-test="call-stats"
          >
            <h3>{{ t('agentTasks.stats.title') }} <HelpTip :content="t('agentTasks.stats.note')" /></h3>
            <div class="stat-grid">
              <div class="stat">
                <span class="stat-num">{{ stats.allowed }}</span>
                <span class="stat-label">{{ t('agentTasks.stats.labels.allowed') }}</span>
              </div>
              <div class="stat">
                <span
                  class="stat-num"
                  :class="{ 'stat-num--flag': stats.blocked > 0 }"
                  data-test="stat-blocked"
                >{{ stats.blocked }}</span>
                <span class="stat-label">{{ t('agentTasks.stats.labels.blocked') }}</span>
              </div>
              <div class="stat">
                <span class="stat-num">{{ stats.unknown }}</span>
                <span class="stat-label">{{ t('agentTasks.stats.labels.unknown') }}</span>
              </div>
            </div>
          </div>
        </div>
        <ToolCallLedger
          :key="taskId"
          :query="{ access_request_id: taskId }"
          :targets="ledgerTargets"
        />
      </section>
      <section data-test="task-reports">
        <header class="sect-head">
          <div>
            <h2>
              {{ t('agentTasks.sections.reports') }} <HelpTip :content="`${t('agentTasks.sectionHints.reports')}\n${t('agentTasks.reportWindow')}`" />
            </h2>
          </div>
        </header>
        <p
          class="field-value"
          data-test="report-boundary"
        >
          {{ t('agentTasks.selfReport') }}
        </p>
        <p
          v-if="reports.missing_report_at_close"
          class="field-value"
          data-test="missing-report"
        >
          {{ t('agentTasks.missingAtClose', { time: formatDateTime(reports.closed_at) }) }}
        </p>
        <EmptyState
          v-if="!reports.total"
          :title="t('agentTasks.noReports')"
          :hint="t('agentTasks.reportWindow')"
          :icon="FileText"
        />
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
import { computed, reactive, ref, watch, onBeforeUnmount } from 'vue'
import { useRoute } from 'vue-router'
import { FileText, PlugZap } from 'lucide-vue-next'
import { t } from '@/i18n'
import { getAgentTask, getAgentToolCalls } from '@/api/agentTasks'
import { getSessionList } from '@/api/sessions'
import { resolveApiError } from '@/api/error'
import { formatDateTime } from '@/utils/format'
// 撤權斷線的措辭與會話列表、詳情同源（enum.endReason.revoked），三畫面不各說各話
import { getEndReasonText } from '@/utils/end-reason'
import { useAssetLabels } from '@/composables/useAssetLabels'
import { setDetailSubject, clearDetailSubject, briefSubject } from '@/utils/detailTitle'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import HelpTip from '@/components/HelpTip.vue'
import PrincipalBadge from '@/components/agent/PrincipalBadge.vue'
import ToolCallLedger from '@/components/agent/ToolCallLedger.vue'
const route = useRoute(), taskId = computed(() => Number(route.params.requestId))
const approvalPage = ref(1), approvalTotal = ref(0)
const task = ref(null), reports = ref({ versions: [], total: 0 }), latest = ref(null), sessions = ref([]), sessionTotal = ref(0), sessionPage = ref(1), reportPage = ref(1), showVersions = ref(false), error = ref(''), sessionError = ref(''), loading = ref(false)
const stats = reactive({ allowed: 0, blocked: 0, unknown: 0, loaded: false })
// 讀不到統計時要說「未知」並可就地重試，不能一直停在「統計中」
const statsFailed = ref(false)
const assetLabels = useAssetLabels(() => (task.value?.items || []).map(item => ({ id: item.asset_id, name: item.asset?.name || (task.value.asset_id === item.asset_id ? task.value.asset?.name : '') })))
// 契約在「申請人即執行者」時 executor_user_id 回 null，但 executor 物件帶得到 id。
// 只判前者時「看鑰匙」直達永不渲染；任一有值即可定位主體
const executorId = computed(() => task.value?.executor_user_id || task.value?.executor?.id || null)
const closedAt = computed(() => task.value?.closed_at || reports.value?.closed_at || '')
// 標題帶主旨：單看「任務 91」答不出這張單在做什麼，麵包屑也一樣
const taskTitle = computed(() => {
  const subject = briefSubject(task.value?.reason)
  return subject
    ? t('agentTasks.detailTitleNamed', { id: taskId.value, subject })
    : t('agentTasks.detailTitle', { id: taskId.value })
})
function approvedEnd(item) {
  const start = Date.parse(item.approved_date_start)
  return Number.isFinite(start) && item.approved_duration_minutes != null ? formatDateTime(new Date(start + item.approved_duration_minutes * 60000)) : t('agentSession.unknown')
}
const visibleReports = computed(() => showVersions.value ? reports.value.versions : latest.value ? [latest.value] : [])
const scopeText = accounts => accounts?.length ? accounts.join(t('common.listSeparator')) : t('multiRequest.allAccounts')
// An approval overwrites the item account scope; requested_accounts is the pre-decision
// scope preserved in the snapshot, and null means it was never preserved, not empty.
const sameScope = (a, b) => JSON.stringify([...(a || [])].sort()) === JSON.stringify([...(b || [])].sort())
const compareItems = computed(() => (task.value?.items || []).map(item => {
  const approved = item.status === 'approved', decided = item.status !== 'pending'
  const requestedMinutes = task.value?.requested_duration_minutes ?? null
  const approvedMinutes = item.approved_duration_minutes ?? null
  const requestedAccounts = item.requested_accounts ?? (approved ? null : item.accounts || [])
  const durationReduced = approved && approvedMinutes != null && requestedMinutes != null && approvedMinutes < requestedMinutes
  // A decision can only narrow the scope, so any difference from the request is a narrowing.
  const accountsReduced = approved && requestedAccounts !== null && !sameScope(requestedAccounts, item.accounts)
  const reduced = durationReduced || accountsReduced
  // 申請當時的帳號範圍沒留存時，比不出帳號有沒有被縮限：不得宣稱「照申請核准」，
  // 只能就時長陳述，並在標籤上說明比較不完整
  const scopeUnknown = approved && requestedAccounts === null
  const headLabel = !decided
    ? t('agentTasks.compare.undecided')
    : !approved
      ? t('agentTasks.compare.notApproved')
      : scopeUnknown
        ? t(durationReduced ? 'agentTasks.compare.durationReducedScopeUnknown' : 'agentTasks.compare.scopeUnknown')
        : t(reduced ? 'agentTasks.compare.reduced' : 'agentTasks.compare.asRequested')
  const headType = !decided ? 'info' : approved ? (reduced ? 'warning' : scopeUnknown ? 'info' : 'success') : 'danger'
  return { item, approved, decided, requestedMinutes, approvedMinutes, requestedAccounts, durationReduced, accountsReduced, scopeUnknown, headLabel, headType, narrowed: reduced || (decided && !approved) }
}))
const narrowedCount = computed(() => compareItems.value.filter(entry => entry.narrowed).length)
// 有任一項比不出帳號範圍時，首屏摘要不得說「照申請核准」
const scopeUnknownCount = computed(() => compareItems.value.filter(entry => entry.scopeUnknown).length)
const totalCalls = computed(() => stats.allowed + stats.blocked + stats.unknown)
// The owner comes from the executor projection; sessions carry the owner at connection time.
// 核准註記的 `system` 是機器碼，不是人名：首層一律講人話
const decisionNoteText = note => note === 'system' ? t('agentTasks.autoApprovedNote') : note
const ownerName = computed(() => task.value?.executor?.owner_username || (task.value?.executor?.owner_user_id ? t('agentPrincipals.unavailable') : t('agentSession.unknown')))
// The ledger contract carries no target: the asset and account come from the session rows.
const ledgerTargets = computed(() => Object.fromEntries(sessions.value.map(session => [session.id, { asset: session.asset?.name || '', account: session.account_username || '' }])))
const sessionEnded = session => !!session.end_time || ['disconnected', 'closed', 'terminated', 'ended'].includes(session.status)
function isAutoApproved(item) {
  if (task.value?.auto_approved) return true
  try { return JSON.parse(item.policy_snapshot || '{}').required_approvals === 0 } catch { return false }
}
let epoch = 0, sessionEpoch = 0, reportEpoch = 0, approvalEpoch = 0, statsEpoch = 0
async function loadStats() {
  const version = ++statsEpoch
  stats.loaded = false; statsFailed.value = false
  const buckets = ['allowed', 'denied', 'breaker', 'rate_limited', 'pending']
  try {
    const totals = await Promise.all(buckets.map(decision => getAgentToolCalls({ access_request_id: taskId.value, decision, offset: 0, limit: 1 }).then(response => response.total || 0)))
    if (version !== statsEpoch) return
    stats.allowed = totals[0]; stats.blocked = totals[1] + totals[2] + totals[3]; stats.unknown = totals[4]; stats.loaded = true
  } catch { if (version === statsEpoch) { stats.loaded = false; statsFailed.value = true } }
}
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
    setDetailSubject(task.value?.reason)
    await loadSessions()
    loadStats()
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
onBeforeUnmount(() => { epoch++; sessionEpoch++; reportEpoch++; approvalEpoch++; statsEpoch++; clearDetailSubject() })
</script>
<style scoped>
.task-detail { color: var(--ot-text-primary); }
.task-sections > section { padding: var(--ot-space-lg); margin-top: var(--ot-space-lg); background: var(--ot-bg-surface); border: 1px solid var(--ot-border-subtle); border-radius: var(--ot-radius-lg); }
/* 三階：區塊標題（lg／600）> 本文（md／主文字色）> 說明句（sm／次要色）。
   本文一度整片落在次要色上，於是標題、說明與數字看起來同一階 */
h2 { font-size: var(--ot-font-size-lg); font-weight: 600; margin: 0; }
h3 { font-size: var(--ot-font-size-lg); font-weight: 600; }
p { color: var(--ot-text-primary); font-size: var(--ot-font-size-md); }
dt { color: var(--ot-text-secondary); } a { color: var(--ot-primary); }
.sect-head { display: flex; align-items: flex-start; gap: var(--ot-space-sm); margin-bottom: var(--ot-space-md); }
.sect-hint { margin: var(--ot-space-xs) 0 0; font-size: var(--ot-font-size-sm); color: var(--ot-text-secondary); }
.field-label { margin: var(--ot-space-md) 0 var(--ot-space-xs); font-size: var(--ot-font-size-sm); color: var(--ot-text-secondary); }
.field-value { margin: 0 0 var(--ot-space-xs); }
/* 標籤欄固定寬、值欄自適應；兩格同列等高（預設 stretch）使中線一致，
   列距純由 row-gap 決定——說明句一旦塞進值格就會把該列撐高、中線就歪了，
   因此說明句自成一列（dl-note）而不是掛在值後面 */
dl { display: grid; grid-template-columns: 9em minmax(0, 1fr); gap: var(--ot-space-sm) var(--ot-space-md); } dd { margin: 0; }
.exec-cell :deep(.principal-badge) { flex-direction: row; align-items: center; }
.cmp { border: 1px solid var(--ot-border-subtle); border-radius: var(--ot-radius-md); overflow: hidden; margin-bottom: var(--ot-space-md); }
.cmp-head { display: flex; align-items: center; gap: var(--ot-space-sm); padding: var(--ot-space-sm) var(--ot-space-md); background: var(--ot-bg-elevated); border-bottom: 1px solid var(--ot-border-subtle); }
.cmp-asset { font-weight: 600; }
.cmp-body { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); }
.cmp-col { padding: var(--ot-space-md); }
.cmp-col + .cmp-col { border-inline-start: 1px solid var(--ot-border-subtle); }
.cmp-col-h { display: block; margin-bottom: var(--ot-space-sm); font-size: var(--ot-font-size-sm); color: var(--ot-text-secondary); }
.cmp-row { display: flex; gap: var(--ot-space-sm); align-items: baseline; padding: var(--ot-space-xs) 0; }
.cmp-key { width: 7em; flex-shrink: 0; color: var(--ot-text-secondary); font-size: var(--ot-font-size-sm); }
.cmp-val { flex: 1; min-width: 0; overflow-wrap: anywhere; color: var(--ot-text-primary); }
.cmp-val-cut { font-weight: 600; }
.cmp-val p { margin: var(--ot-space-xs) 0 0; font-size: var(--ot-font-size-sm); }
.task-summary { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: var(--ot-space-md); margin-top: var(--ot-space-lg); padding: var(--ot-space-md); background: var(--ot-bg-surface); border: 1px solid var(--ot-border-subtle); border-radius: var(--ot-radius-lg); }
/* subgrid：各格的標籤列與值列共用同一組列軌，哪一語言的標籤折行都不會讓
   同列的值互相錯開（日文量測曾差 3px） */
.task-summary > div { display: grid; grid-template-rows: subgrid; grid-row: span 2; gap: var(--ot-space-xs); }
.task-summary dt { font-size: var(--ot-font-size-sm); color: var(--ot-text-secondary); margin-bottom: 0; }
.task-summary dd { margin: 0; color: var(--ot-text-primary); font-size: var(--ot-font-size-xl); font-weight: 600; line-height: 1.3; overflow-wrap: anywhere; }
.task-summary__flag { color: var(--ot-warning); }
@media (max-width: 75rem) { .task-summary { grid-template-columns: repeat(3, minmax(0, 1fr)); } }
@media (max-width: 45rem) { .task-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
.activity-cards { display: flex; flex-wrap: wrap; gap: var(--ot-space-md); margin-bottom: var(--ot-space-md); }
.activity-card { flex: 1 1 320px; min-width: 0; border: 1px solid var(--ot-border-subtle); border-radius: var(--ot-radius-md); padding: var(--ot-space-md); }
.activity-card h3 { margin: 0 0 var(--ot-space-sm); }
.session-line { display: flex; flex-wrap: wrap; align-items: center; gap: var(--ot-space-sm); }
.session-asset { font-weight: 600; }
.task-item + .task-item { margin-top: var(--ot-space-sm); border-top: 1px solid var(--ot-border-subtle); padding-top: var(--ot-space-sm); }
.task-item p { margin: var(--ot-space-xs) 0 0; font-size: var(--ot-font-size-sm); color: var(--ot-text-secondary); }
/* 數字先被看到，標籤其次：數字 xl／主文字色，標籤 sm／次要色 */
.stat-grid { display: flex; flex-wrap: wrap; gap: var(--ot-space-lg); margin: 0; }
.stat { display: flex; flex-direction: column; }
.stat-num { margin: 0; font-size: var(--ot-font-size-xl); font-weight: 600; line-height: 1.2; color: var(--ot-text-primary); }
.stat-num--flag { color: var(--ot-danger); }
.stat-label { font-size: var(--ot-font-size-sm); color: var(--ot-text-secondary); }
pre { white-space: pre-wrap; overflow-wrap: anywhere; font-family: var(--ot-font-mono); font-size: var(--ot-font-size-sm); color: var(--ot-text-primary); }
</style>
