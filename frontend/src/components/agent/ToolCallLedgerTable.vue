<template>
  <table
    class="ledger"
    data-test="ledger-table"
  >
    <thead>
      <tr>
        <th class="col-time">
          {{ t('agentLedger.columns.time') }}
        </th>
        <th class="col-action">
          {{ t('agentLedger.columns.action') }}
        </th>
        <th class="col-target">
          {{ t('agentLedger.columns.target') }}
        </th>
        <th class="col-decision">
          {{ t('agentLedger.columns.decision') }}
        </th>
        <th class="col-num">
          {{ t('agentLedger.columns.masked') }}
        </th>
        <th class="col-num">
          {{ t('agentLedger.columns.duration') }}
        </th>
        <th>{{ t('agentLedger.columns.link') }}</th>
      </tr>
    </thead>
    <tbody
      v-for="row in rows"
      :key="row.id"
      data-test="ledger-row"
    >
      <tr
        class="tool-ledger__summary"
        :class="{ blocked: blocked(row) }"
      >
        <td><time>{{ formatDateTime(row.created_at) }}</time></td>
        <td><strong data-test="tool-action">{{ toolLabel(row.tool) }}</strong></td>
        <td data-test="ledger-target">
          <template v-if="target(row)">
            <span class="target-main">{{ target(row).asset || placeholder }}</span> · <span class="mono">{{ target(row).account || placeholder }}</span>
          </template>
          <template v-else-if="!row.session_id">
            {{ t('agentLedger.noSession') }}
          </template>
          <template v-else>
            {{ placeholder }}
          </template>
        </td>
        <td>
          <el-tag
            :type="decisionTagType(row.decision)"
            data-test="ledger-decision"
          >
            {{ decisionLabel(row.decision) }}
          </el-tag>
        </td>
        <td class="col-num">
          <el-tag
            v-if="row.masked_count > 0"
            type="info"
            data-test="masked-count"
          >
            {{ row.masked_count }}
          </el-tag><span
            v-else
            data-test="masked-count"
          >0</span>
        </td>
        <td class="col-num">
          {{ t('agentLedger.durationValue', { n: row.duration_ms }) }}
        </td>
        <td>
          <a
            v-if="linkMode === 'session' && row.session_id"
            :href="`/sessions/${row.session_id}`"
          >{{ t('agentLedger.session', { id: row.session_id }) }}</a><a
            v-else-if="linkMode === 'task' && row.access_request_id"
            :href="`/audit/agent-tasks/${row.access_request_id}`"
          >{{ t('agentLedger.task', { id: row.access_request_id }) }}</a><span v-else>{{ placeholder }}</span>
        </td>
      </tr>
      <tr
        v-if="row.decision === 'pending'"
        class="why"
      >
        <td colspan="7">
          {{ t('agentLedger.pendingBoundary') }}
        </td>
      </tr>
      <tr
        v-if="row.denial_code"
        class="why denied"
      >
        <td
          colspan="7"
          data-test="denial-explanation"
        >
          {{ denialLabel(row.denial_code) }}
        </td>
      </tr>
      <tr
        v-if="blocked(row) && row.args_retained && typeof row.args_redacted?.command === 'string'"
        class="why denied"
      >
        <td colspan="7">
          <code data-test="denied-command-preview">{{ row.args_redacted.command }}</code>
          <code
            v-if="row.denial_code"
            class="denied-code"
            data-test="denied-reason-code-preview"
          >{{ row.denial_code }}</code>
        </td>
      </tr>
      <tr class="more">
        <td colspan="7">
          <details>
            <summary>{{ t('agentLedger.details') }}</summary>
            <dl>
              <dt>{{ t('agentLedger.seq') }}</dt><dd><code>{{ row.seq }}</code></dd>
              <dt>{{ t('agentLedger.reasonCode') }}</dt><dd><code data-test="denial-code">{{ row.denial_code || placeholder }}</code></dd>
              <dt>{{ t('agentLedger.toolName') }}</dt><dd><code>{{ row.tool }}</code></dd>
              <dt>{{ t('agentLedger.result') }}</dt><dd>{{ row.decision === 'pending' ? t('agentLedger.unknown') : row.result_status || t('agentLedger.unknown') }}</dd>
              <dt>{{ t('agentLedger.arguments') }}</dt><dd>
                <span
                  v-if="!row.args_retained"
                  data-test="arguments-not-retained"
                >{{ t('agentLedger.argumentsNotRetained') }}</span>
                <template v-else>
                  <div class="argument-actions">
                    <el-tag
                      v-if="hasRevealed(row)"
                      class="ot-tag-neutral"
                      data-test="arguments-revealed"
                    >
                      {{ t('agentLedger.revealed') }}
                    </el-tag>
                    <el-button
                      v-else-if="canReveal && row.masked_count > 0"
                      link
                      type="primary"
                      data-test="reveal-arguments"
                      @click="openReveal(row)"
                    >
                      {{ t('agentLedger.revealArguments') }}
                    </el-button>
                  </div>
                  <div
                    v-if="handleFingerprint(argumentsFor(row))"
                    class="handle-fingerprint"
                  >
                    <code>{{ handleFingerprint(argumentsFor(row)) }}</code>
                    <HelpTip
                      :content="t('agentLedger.handleFingerprint')"
                    />
                  </div>
                  <pre
                    v-if="Object.keys(otherArguments(argumentsFor(row))).length"
                    data-test="ledger-arguments"
                  >{{ JSON.stringify(otherArguments(argumentsFor(row)), null, 2) }}</pre>
                </template>
              </dd>
              <dt>{{ t('agentLedger.digest') }}</dt><dd><code>{{ row.result_digest || t('agentLedger.unavailable') }}</code></dd>
              <dt>{{ t('agentLedger.excerpt') }}</dt><dd>
                <p data-test="excerpt-boundary">
                  {{ t('agentLedger.excerptBoundary') }}
                </p><pre>{{ row.result_excerpt || t('agentLedger.unavailable') }}</pre>
              </dd>
            </dl>
          </details>
        </td>
      </tr>
    </tbody>
  </table>
  <el-dialog
    v-model="revealDialogVisible"
    :title="t('agentLedger.revealArguments')"
    width="480px"
    @closed="clearReveal"
  >
    <p>{{ t('agentLedger.revealReasonHint') }}</p>
    <el-input
      v-model="revealReason"
      type="textarea"
      :rows="3"
      :placeholder="t('agentLedger.revealReason')"
      data-test="reveal-reason"
    />
    <p
      v-if="revealError"
      class="reveal-error"
      data-test="reveal-error"
    >
      {{ revealError }}
    </p>
    <template #footer>
      <el-button @click="revealDialogVisible = false">
        {{ t('common.cancel') }}
      </el-button>
      <el-button
        type="primary"
        :disabled="!validReason || revealSubmitting"
        :loading="revealSubmitting"
        data-test="reveal-submit"
        @click="submitReveal"
      >
        {{ t('agentLedger.revealArguments') }}
      </el-button>
    </template>
  </el-dialog>
</template>
<script setup>
import { ref, computed, watch } from 'vue'
import i18n, { t } from '@/i18n'
import { resolveApiError } from '@/api/error'
import { getAgentToolCallArguments } from '@/api/agentTasks'
import { useRoles } from '@/composables/useRoles'
import HelpTip from '@/components/HelpTip.vue'
import { formatDateTime } from '@/utils/format'
// targets maps session id to the asset and account that session reached; the ledger
// contract carries no target of its own, so an unmatched session stays a placeholder.
const props = defineProps({
  rows: { type: Array, default: () => [] },
  targets: { type: Object, default: () => ({}) },
  linkMode: { type: String, default: 'session' },
})
const placeholder = '—'
const { isPrivileged: canReveal } = useRoles()
const revealed = ref({})
const revealDialogVisible = ref(false)
const revealReason = ref('')
const revealError = ref('')
const revealSubmitting = ref(false)
const selectedRow = ref(null)
const validReason = computed(() => {
  const reason = revealReason.value.trim()
  return reason.length > 0 && new TextEncoder().encode(reason).length <= 1000
})
const hasRevealed = row => Object.prototype.hasOwnProperty.call(revealed.value, row.id)
const argumentsFor = row => hasRevealed(row) ? revealed.value[row.id] : row.args_redacted
const handleFingerprint = value => typeof value?.session_handle === 'string' && value.session_handle.startsWith('fp:')
  ? value.session_handle : ''
const otherArguments = value => {
  if (!value || typeof value !== 'object') return {}
  if (!handleFingerprint(value)) return value
  const rest = { ...value }
  delete rest.session_handle
  return rest
}
watch(() => props.rows, () => {
  revealed.value = {}
  revealDialogVisible.value = false
})
const openReveal = row => {
  selectedRow.value = row
  revealReason.value = ''
  revealError.value = ''
  revealDialogVisible.value = true
}
const clearReveal = () => {
  selectedRow.value = null
  revealReason.value = ''
  revealError.value = ''
}
const submitReveal = async () => {
  if (!selectedRow.value || !validReason.value || revealSubmitting.value) return
  revealSubmitting.value = true
  revealError.value = ''
  try {
    const response = await getAgentToolCallArguments(selectedRow.value.id, revealReason.value.trim())
    revealed.value[selectedRow.value.id] = response.data.arguments
    revealDialogVisible.value = false
  } catch (error) {
    revealError.value = resolveApiError(error?.response?.data, error?.response?.status, t('agentLedger.revealFailed'))
  } finally {
    revealSubmitting.value = false
  }
}
// The ledger row carries its own target where the contract provides one; the session
// list is the fallback for rows recorded before that projection existed.
const target = row => row.asset_name || row.account_username
  ? { asset: row.asset_name, account: row.account_username }
  : props.targets[row.session_id] || null
const decisions = ['pending', 'allowed', 'denied', 'breaker', 'rate_limited']
const decisionLabel = value => decisions.includes(value) ? t(`agentLedger.decisions.${value}`) : t('agentLedger.unknown')
const decisionTagType = value => value === 'allowed' ? 'success' : value === 'pending' ? 'warning' : decisions.includes(value) ? 'danger' : 'info'
const blocked = row => ['denied', 'breaker', 'rate_limited'].includes(row.decision)
const toolLabel = tool => Object.prototype.hasOwnProperty.call(i18n.global.getLocaleMessage(i18n.global.locale.value).agentLedger.tools, tool) ? t(`agentLedger.tools.${tool}`) : t('agentLedger.unknownTool')
const denialLabel = code => resolveApiError({ code }, 403, t('agentLedger.unknownReason'))
</script>
<script>
export default { name: 'ToolCallLedgerTable' }
</script>
<style scoped>
.ledger { width: 100%; border-collapse: collapse; color: var(--ot-text-primary); }
.ledger th { background: var(--ot-bg-elevated); color: var(--ot-text-secondary); font-weight: 600; text-align: start; padding: var(--ot-space-sm); border-bottom: 1px solid var(--ot-border-subtle); white-space: nowrap; }
.ledger td { padding: var(--ot-space-sm); vertical-align: middle; border-bottom: 1px solid var(--ot-border-subtle); }
.col-time { width: 12em; } .col-action { width: 14em; } .col-target { width: 18em; } .col-decision { width: 8em; }
.col-num { width: 7em; text-align: end; font-variant-numeric: tabular-nums; }
tr.blocked td { background: color-mix(in srgb, var(--ot-danger) 7%, transparent); border-bottom-color: transparent; }
tr.why td { padding-top: 0; color: var(--ot-text-secondary); font-size: var(--ot-font-size-sm); }
tr.why.denied td { color: var(--ot-danger); }
tr.more td { padding-top: 0; }
.target-main { color: var(--ot-text-primary); }
.mono { font-family: var(--ot-font-mono); font-size: var(--ot-font-size-sm); color: var(--ot-text-secondary); }
dl { display: grid; grid-template-columns: auto minmax(0, 1fr); gap: var(--ot-space-sm) var(--ot-space-md); margin: var(--ot-space-sm) 0 0; }
dt { color: var(--ot-text-secondary); font-size: var(--ot-font-size-sm); }
dd { margin: 0; overflow-wrap: anywhere; }
p { color: var(--ot-text-secondary); font-size: var(--ot-font-size-sm); }
pre { white-space: pre-wrap; overflow-wrap: anywhere; font-family: var(--ot-font-mono); font-size: var(--ot-font-size-sm); }
.argument-actions { display: flex; align-items: center; gap: var(--ot-space-sm); }
.handle-fingerprint { display: flex; align-items: center; gap: var(--ot-space-xs); font-family: var(--ot-font-mono); }
.denied-code { margin-inline-start: var(--ot-space-sm); }
.reveal-error { color: var(--ot-danger); }
a { color: var(--ot-primary); }
summary { cursor: pointer; }
</style>
