<template>
  <div>
    <h4
      class="section-title"
      data-test="setup-result-title"
    >
      {{ resultTitle }}
    </h4>
    <p
      v-if="phase === 'run' && running"
      class="field-hint"
      data-test="setup-running"
    >
      {{ $t('groupSetup.running') }}
    </p>
    <ol
      class="result-list"
      data-test="setup-result"
    >
      <li
        v-for="(row, index) in run.rows"
        :key="index"
        :class="`state-${row.state}`"
        :data-test="`setup-row-${index + 1}`"
      >
        <div class="result-line">
          <span class="step-no">{{ index + 1 }}.</span>
          <span class="result-task">{{ taskLines[index] }}</span>
          <strong
            class="result-state"
            :data-test="`setup-row-${index + 1}-state`"
            :data-state="row.state"
          >{{ stateText(row) }}</strong>
        </div>
        <p
          v-if="rowDetail(row, index)"
          class="field-hint"
          :data-test="`setup-row-${index + 1}-detail`"
        >
          {{ rowDetail(row, index) }}
        </p>
        <p
          v-if="row.state === 'differs'"
          class="field-hint"
          data-test="setup-differs"
        >
          {{ $t('groupSetup.differs', { list: readBackText }) }}
        </p>
        <div
          v-if="index === 0 && row.state === 'unconfirmed'"
          class="result-actions"
        >
          <a
            href="/user-groups"
            target="_blank"
            rel="noopener"
            class="hint-link"
            data-test="setup-go-user-groups"
          >{{ $t('identityGroupMappings.goUserGroups') }}</a>
        </div>
      </li>
    </ol>

    <template v-if="phase === 'done'">
      <div class="after-box">
        <strong>{{ $t('groupSetup.nextOptionalTitle') }}</strong>
        <p>{{ $t('groupSetup.nextOptionalBody') }}</p>
        <p>{{ $t('userDetail.change.connectionFixed') }}</p>
        <p
          v-if="!canGoAuthorizations"
          data-test="setup-no-authz"
        >
          {{ $t('groupSetup.noAuthzNote') }}
        </p>
      </div>
      <div class="result-actions">
        <a
          v-if="canGoAuthorizations"
          :href="`/authorizations?user_group_id=${run.groupId}`"
          target="_blank"
          rel="noopener"
          class="hint-link"
          data-test="setup-go-authorizations"
        >{{ $t('groupSetup.goAuthorizations') }}</a>
        <a
          :href="groupRolesHref"
          target="_blank"
          rel="noopener"
          class="hint-link"
          data-test="setup-open-group-roles"
        >{{ $t('groupSetup.openGroupRoles') }}</a>
      </div>
    </template>
    <template v-else-if="!running">
      <p
        class="field-hint"
        data-test="setup-keep-note"
      >
        {{ $t(hasDoneStep ? 'groupSetup.keepNote' : 'groupSetup.keepNoteNone') }}
      </p>
      <p
        v-if="showNoImpact"
        class="field-hint"
        data-test="setup-no-impact"
      >
        {{ $t('groupSetup.noImpact') }}
      </p>
      <div class="result-actions">
        <a
          v-if="run.rows[0].state === 'done'"
          :href="groupRolesHref"
          target="_blank"
          rel="noopener"
          class="hint-link"
          data-test="setup-open-group-roles"
        >{{ $t('groupSetup.openGroupRoles') }}</a>
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { t } from '@/i18n'
import { roleLabel } from '@/constants/roles'
import { apiErrorText } from '../groupSetupOutcome'

/** 「建立群組並設定角色與範圍」抽屜的結果畫面：逐項呈現三件事的寫入結果與後續連結。 */
const props = defineProps({
  phase: { type: String, required: true },
  running: { type: Boolean, default: false },
  run: { type: Object, required: true },
  resultTitle: { type: String, default: '' },
  taskLines: { type: Array, default: () => [] },
  canGoAuthorizations: { type: Boolean, default: false },
  groupRolesHref: { type: String, default: '' },
  showNoImpact: { type: Boolean, default: false },
})

const hasDoneStep = computed(() => props.run.rows.some((r) => r.state === 'done'))
const stateText = (row) => {
  switch (row.state) {
    case 'done': return t('groupSetup.state.done')
    case 'rejected': return t('groupSetup.state.rejected')
    case 'notWritten': return t('groupSetup.state.notWritten')
    case 'unconfirmed': return t('groupSetup.state.unconfirmed')
    case 'differs': return t('groupSetup.state.differs')
    case 'checking': return t('groupSetup.state.checking')
    default: return t('groupSetup.state.notRun')
  }
}
const rejectedReason = (row) => apiErrorText(row.code, t) || t('groupSetup.failureGeneric')
const rowDetail = (row, index) => {
  if (row.state === 'rejected') return rejectedReason(row)
  if (row.state === 'notWritten') return t(`groupSetup.notWritten.${index + 1}`)
  if (row.state === 'unconfirmed') {
    return row.reason === 'sameName' ? t('groupSetup.unconfirmedSameName') : t(`groupSetup.unconfirmedRead.${index + 1}`)
  }
  return ''
}
const readBackText = computed(() =>
  props.run.readBack
    .map((b) => `${roleLabel(b.role_name)}（${b.scope === 'nodes' ? t('roleNodePicker.nodeCountOnly', { n: (b.node_ids || []).length }) : t('roleNodePicker.modeAll')}）`)
    .join('、')
)
</script>

<style scoped>
.step-no {
  display: inline-block;
  min-width: 1.5em;
  font-weight: 600;
}
.after-box {
  margin: 0 0 var(--ot-space-md);
  padding: var(--ot-space-sm) var(--ot-space-md);
  background: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
}
.after-box p {
  margin: var(--ot-space-xs) 0 0;
  color: var(--ot-text-secondary);
}
.section-title {
  margin: var(--ot-space-md) 0 var(--ot-space-xs);
  font-size: var(--ot-font-size-md);
  color: var(--ot-text-primary);
}
.field-hint {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
  margin-top: var(--ot-space-xs);
}
.result-list {
  list-style: none;
  margin: 0 0 var(--ot-space-sm);
  padding: 0;
  display: grid;
  gap: var(--ot-space-sm);
}
.result-line {
  display: flex;
  gap: var(--ot-space-xs);
  align-items: baseline;
  flex-wrap: wrap;
}
.result-task {
  flex: 1;
  min-width: 12em;
  overflow-wrap: anywhere;
}
.result-state {
  white-space: nowrap;
}
.state-rejected .result-state,
.state-unconfirmed .result-state,
.state-notWritten .result-state,
.state-differs .result-state {
  color: var(--ot-danger, var(--el-color-danger));
}
.result-actions {
  display: flex;
  gap: var(--ot-space-md);
  flex-wrap: wrap;
  margin-top: var(--ot-space-sm);
}
.hint-link {
  color: var(--el-color-primary);
  font-size: var(--ot-font-size-sm);
  text-decoration: none;
}
</style>
