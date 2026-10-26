<template>
  <div class="group-setup-root">
    <el-drawer
      v-model="visible"
      :title="$t('groupSetup.title')"
      size="min(640px, 100vw)"
      :close-on-click-modal="false"
      :before-close="beforeClose"
      class="group-setup-drawer"
      data-test="group-setup-drawer"
    >
      <div
        ref="focusAnchor"
        class="focus-anchor"
        tabindex="-1"
        data-test="setup-focus-anchor"
      >
        <!-- 表單：三步（一般編號，不使用圓框步驟條） -->
        <div v-show="phase === 'form'">
          <ol
            class="steps-head"
            data-test="setup-steps"
          >
            <li
              v-for="n in 3"
              :key="n"
              :class="{ current: step === n, finished: step > n }"
              :data-test="`setup-step-${n}`"
              :aria-current="step === n ? 'step' : undefined"
            >
              <span class="step-no">{{ n }}.</span>
              <svg
                v-if="step > n"
                class="step-check"
                viewBox="0 0 16 16"
                width="14"
                height="14"
                aria-hidden="true"
                data-test="setup-step-check"
              ><path
                d="m3 8.5 3.2 3.2 6.8-6.9"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
              /></svg>
              <span class="step-name">{{ $t(`groupSetup.stepName${n}`) }}</span>
            </li>
          </ol>

          <section
            v-show="step === 1"
            data-test="setup-panel-1"
          >
            <p class="note-box">
              {{ $t('groupSetup.step1Intro') }}
            </p>
            <el-form
              label-position="top"
              @submit.prevent
            >
              <el-form-item
                :label="$t('groupSetup.groupName')"
                required
              >
                <el-input
                  v-model="form.name"
                  maxlength="100"
                  :disabled="groupLocked"
                  :placeholder="$t('userGroups.namePlaceholder')"
                  data-test="setup-name"
                />
                <div
                  v-if="nameError"
                  class="field-error"
                  data-test="setup-name-error"
                >
                  {{ nameError }}
                </div>
                <div
                  v-if="groupLocked"
                  class="field-hint"
                  data-test="setup-name-locked"
                >
                  {{ $t('groupSetup.nameLocked') }}
                </div>
              </el-form-item>
              <el-form-item :label="$t('groupSetup.groupDesc')">
                <el-input
                  v-model="form.description"
                  type="textarea"
                  :rows="3"
                  maxlength="500"
                  :disabled="groupLocked"
                  data-test="setup-desc"
                />
              </el-form-item>
              <el-form-item
                v-if="carried"
                :label="$t('identityGroupMappings.columns.externalGroup')"
              >
                <div
                  class="carried-value"
                  data-test="setup-carried-match"
                >
                  {{ carried.matchValue }}
                </div>
                <div class="field-hint">
                  {{ $t('groupSetup.carriedHint') }}
                </div>
              </el-form-item>
            </el-form>
          </section>

          <section
            v-show="step === 2"
            data-test="setup-panel-2"
          >
            <p
              class="note-box"
              data-test="setup-scope-banner"
            >
              <strong>{{ $t('roleScope.bannerTitle') }}</strong>
              {{ $t('roleScope.bannerBody') }}
              {{ $t('userDetail.change.connectionFixed') }}
            </p>
            <h4 class="section-title">
              {{ $t('groupSetup.step2Title', { group: form.name.trim() || $t('groupSetup.newGroup') }) }}
            </h4>
            <p class="field-hint">
              {{ $t('groupSetup.step2Same') }}
            </p>
            <GroupRoleEditor
              :key="editorKey"
              ref="editor"
              :definitions="definitions"
              :bindings="editorBindings"
              :preselect-ids="preselectIds"
              @update:draft="(v) => (roleDraft = v)"
            />
            <p
              v-if="!roleDraft.roleIds.length"
              class="field-hint"
              data-test="setup-need-role"
            >
              {{ $t('groupSetup.step2NeedRole') }}
            </p>
          </section>

          <section
            v-show="step === 3"
            data-test="setup-panel-3"
          >
            <el-form
              label-position="top"
              @submit.prevent
            >
              <el-form-item
                :label="$t('identityGroupMappings.columns.externalGroup')"
                required
              >
                <el-autocomplete
                  v-model="form.matchValue"
                  :fetch-suggestions="suggestExternalGroups"
                  value-key="value"
                  style="width: 100%"
                  maxlength="500"
                  :placeholder="matchPlaceholder"
                  data-test="setup-match"
                />
                <div
                  class="field-hint"
                  data-test="setup-match-hint"
                >
                  {{ matchHint }}
                </div>
                <div
                  v-if="isEntraSource"
                  class="field-hint"
                >
                  {{ $t('identitySources.mapping.entraMatchHint') }}
                </div>
              </el-form-item>
              <el-form-item :label="$t('identityGroupMappings.fields.note')">
                <el-input
                  v-if="dictEntry"
                  :model-value="dictEntry.note || ''"
                  readonly
                  data-test="setup-note-readonly"
                />
                <el-input
                  v-else
                  v-model="form.note"
                  maxlength="200"
                  data-test="setup-note"
                />
                <div
                  v-if="dictEntry"
                  class="field-hint"
                  data-test="setup-note-shared"
                >
                  {{ $t('groupSetup.noteSharedReadonly') }}
                </div>
                <div
                  v-if="carriedNoteIgnored"
                  class="field-hint"
                  data-test="setup-note-ignored"
                >
                  {{ $t('groupSetup.carriedNoteIgnored', { note: carried.note }) }}
                </div>
              </el-form-item>
            </el-form>

            <p class="section-title">
              {{ $t('groupSetup.step3Lead') }}
            </p>
            <ol
              class="task-list"
              data-test="setup-tasks"
            >
              <li
                v-for="(line, index) in taskLines"
                :key="index"
                :data-test="`setup-task-${index + 1}`"
              >
                <span class="step-no">{{ index + 1 }}.</span>{{ line }}
              </li>
            </ol>
            <p
              class="field-hint"
              data-test="setup-rule-no-scope"
            >
              {{ $t('groupSetup.ruleNoScope') }}
            </p>

            <div class="after-box">
              <strong>{{ $t('groupSetup.afterTitle') }}</strong>
              <p data-test="setup-after-members">
                {{ afterMembersText }}
              </p>
              <p data-test="setup-after-connection">
                {{ $t('userDetail.change.connectionFixed') }}
              </p>
            </div>
            <div
              v-if="managementHint"
              class="field-hint"
              data-test="setup-management-hint"
            >
              {{ managementHint }}
            </div>
            <div
              v-if="directoryHint"
              class="field-hint"
              data-test="setup-directory-hint"
            >
              {{ directoryHint }}
            </div>
          </section>
        </div>

        <!-- 結果：逐項呈現三件事 -->
        <GroupSetupResult
          v-if="phase !== 'form'"
          :phase="phase"
          :running="running"
          :run="run"
          :result-title="resultTitle"
          :task-lines="taskLines"
          :can-go-authorizations="canGoAuthorizations"
          :group-roles-href="groupRolesHref"
          :show-no-impact="showNoImpact"
        />
      </div>

      <template #footer>
        <div class="drawer-footer">
          <template v-if="phase === 'form'">
            <el-button
              data-test="setup-cancel"
              @click="close"
            >
              {{ $t('common.cancel') }}
            </el-button>
            <el-button
              v-if="step > 1"
              data-test="setup-prev"
              @click="step -= 1"
            >
              {{ $t('groupSetup.prev') }}
            </el-button>
            <el-button
              v-if="step < 3"
              type="primary"
              :disabled="!canNext"
              data-test="setup-next"
              @click="step += 1"
            >
              {{ $t('groupSetup.next') }}
            </el-button>
            <el-button
              v-else
              type="primary"
              :disabled="!canSubmit"
              data-test="setup-submit"
              @click="submit"
            >
              {{ $t('groupSetup.create') }}
            </el-button>
          </template>
          <template v-else-if="phase === 'done'">
            <el-button
              type="primary"
              data-test="setup-finish"
              @click="close"
            >
              {{ $t('groupSetup.finish') }}
            </el-button>
          </template>
          <template v-else>
            <el-button
              :disabled="running"
              data-test="setup-close"
              @click="close"
            >
              {{ $t('common.close') }}
            </el-button>
            <el-button
              v-if="!running && recheckStep !== -1"
              data-test="setup-recheck"
              @click="recheck"
            >
              {{ $t('groupSetup.recheck') }}
            </el-button>
            <el-button
              v-if="!running && retryKind === 'edit'"
              type="primary"
              data-test="setup-edit-roles"
              @click="editRoles"
            >
              {{ $t('groupSetup.backToRoles') }}
            </el-button>
            <el-button
              v-else-if="!running && retryKind"
              type="primary"
              data-test="setup-retry"
              @click="retry"
            >
              {{ $t(`groupSetup.retry.${retryKind}`) }}
            </el-button>
            <el-button
              v-if="!running && canEditRolesAfterReject"
              data-test="setup-edit-roles"
              @click="editRoles"
            >
              {{ $t('groupSetup.backToRoles') }}
            </el-button>
          </template>
        </div>
      </template>
    </el-drawer>

    <DangerComboConfirm
      v-model="rolesConfirm.open"
      :preview="rolesConfirm.preview"
      :unavailable="rolesConfirm.unavailable"
      :notify-message="rolesConfirmNotify"
      @confirm="rolesConfirm.settle(true)"
      @back="rolesConfirm.settle(false)"
    />
    <DangerComboConfirm
      v-model="confirmOpen"
      :preview="confirmPreview"
      :unavailable="confirmUnavailable"
      :notify-message="confirmNotify"
      :footnote="confirmFootnote"
      @back="cancelConfirm"
      @confirm="proceedConfirm"
    />
  </div>
</template>

<script setup>
import { computed, nextTick, reactive, ref, watch } from 'vue'
import { t } from '@/i18n'
import { isEntraIssuer } from '@/utils/entraIssuer'
import { roleLabel } from '@/constants/roles'
import { can } from '@/composables/useCapabilities'
import { canEnter, entryRuleFor } from '@/router/entryRules'
import { managementRoleNames } from '@/views/usergroups/groupProtection'
import DangerComboConfirm from '@/components/DangerComboConfirm.vue'
import GroupRoleEditor from '@/views/usergroups/components/GroupRoleEditor.vue'
import GroupSetupResult from './GroupSetupResult.vue'
import { newRunState, useGroupSetupSubmit } from '../useGroupSetupSubmit'

/**
 * 映射頁的「建立群組並設定角色與範圍」抽屜：1. 群組、2. 角色與管理範圍、3. 外部群組與確認。
 * 送出後依序呼叫三個既有寫入（建立群組、寫入群組的角色指派、建立映射規則），不新增任何寫入路徑。
 * 失敗不等於沒有寫入：確定被拒絕只認 groupSetupOutcome 的封閉清單，其餘一律先以既有讀取核對。
 * 已完成的步驟不自動撤回，重試只做未完成的步驟並沿用已建立的群組。
 */
const props = defineProps({
  sourceType: { type: String, required: true },
  sourceId: { type: [String, Number], required: true },
  sourceName: { type: String, default: '' },
  sourceAddress: { type: String, default: '' },
  definitions: { type: Array, default: () => [] },
  // 該身分來源的外部群組字典：[{ id, match_value, note }]
  externalGroups: { type: Array, default: () => [] },
})
const emit = defineEmits(['closed'])

const ENTRIES_PRESELECT = ['rolesTabHint', 'roleRuleMenu']
const PROTECTED_BUILTIN = new Set(['super_admin', 'security_admin'])
const visible = ref(false)
const phase = ref('form') // form | run | done
const step = ref(1)
const form = reactive({ name: '', description: '', matchValue: '', note: '' })
const carried = ref(null)
const entry = ref('')
const preselectIds = ref([])
const editorKey = ref(0)
const editor = ref(null)
const editorBindings = ref([])
const roleDraft = ref({ roleIds: [], roleNodes: {} })
const nameError = ref('')
const running = ref(false)
const gateBusy = ref(false)
const canAssign = computed(() => can('role:assign'))
const canGoAuthorizations = computed(() => canEnter(entryRuleFor('/authorizations')))
const groupLocked = computed(() => run.groupId != null)
const isDirectorySource = computed(() => props.sourceType === 'ldap')
const isEntraSource = computed(() => props.sourceType === 'oidc' && isEntraIssuer(props.sourceAddress))
const matchPlaceholder = computed(() => (isDirectorySource.value ? t('identitySources.mapping.matchDnPlaceholder') : t('identitySources.mapping.matchClaimValuePlaceholder')))
const matchHint = computed(() => (isDirectorySource.value ? t('identitySources.mapping.matchDnHint') : t('identitySources.mapping.matchClaimValueHint')))
const groupRolesHref = computed(() => `/user-groups/${run.groupId}?tab=roles`)

const defById = (id) => props.definitions.find((d) => d.id === id)
const selectedDefs = computed(() => roleDraft.value.roleIds.map(defById).filter(Boolean))
const managementNames = computed(() =>
  managementRoleNames(roleDraft.value.roleIds, props.definitions).map(roleLabel)
)
const protectedNames = computed(() =>
  selectedDefs.value
    .filter((d) => d.assignment_state === 'protected' || PROTECTED_BUILTIN.has(d.builtin_key))
    .map((d) => roleLabel(d.name))
)

// —— 第 3 步 ——
const matchTrimmed = computed(() => form.matchValue.trim())
const dictEntry = computed(() => props.externalGroups.find((g) => g.match_value === matchTrimmed.value) || null)
const carriedNoteIgnored = computed(() =>
  Boolean(
    dictEntry.value &&
      carried.value &&
      carried.value.matchValue === matchTrimmed.value &&
      (carried.value.note || '') !== (dictEntry.value.note || '')
  )
)
const suggestExternalGroups = (query, callback) =>
  callback(
    props.externalGroups
      .filter((g) => g.match_value.toLowerCase().includes(query.toLowerCase()))
      .map((g) => ({ value: g.match_value, note: g.note }))
  )

const scopeTextOf = (id) => {
  const nodes = roleDraft.value.roleNodes[String(id)]
  if (!Array.isArray(nodes)) return t('roleNodePicker.modeAll')
  return nodes.map((nid) => editor.value?.nodePath(nid) || String(nid)).join('、')
}
const rolesLineText = computed(() =>
  selectedDefs.value.map((d) => `${roleLabel(d.name)}（${scopeTextOf(d.id)}）`).join('、')
)
const groupNameText = computed(() => run.groupName || form.name.trim())
const taskLines = computed(() => [
  t('groupSetup.task1', { group: groupNameText.value }),
  t('groupSetup.task2', { roles: rolesLineText.value }),
  t('groupSetup.task3', { source: props.sourceName, external: matchTrimmed.value, group: groupNameText.value }),
])
const afterMembersText = computed(() =>
  t('groupSetup.afterMembers', {
    external: matchTrimmed.value || t('groupSetup.thisExternalGroup'),
    roles: selectedDefs.value.map((d) => roleLabel(d.name)).join('、'),
  })
)
const managementHint = computed(() =>
  managementNames.value.length
    ? t('identityGroupMappings.managementTarget', { role: managementNames.value.join('、') })
    : ''
)
const directoryHint = computed(() => {
  if (protectedNames.value.length) {
    const role = protectedNames.value.join('、')
    return `${t('identityGroupMappings.protectedTarget', { role })} ${t('identityGroupMappings.externalDirectoryDecides', { role })}`
  }
  return managementNames.value.length
    ? t('identityGroupMappings.externalDirectoryDecides', { role: managementNames.value.join('、') })
    : ''
})

const canNext = computed(() => {
  if (step.value === 1) return Boolean(form.name.trim())
  if (step.value === 2) return roleDraft.value.roleIds.length > 0
  return false
})

const {
  run, rolesPreview, canSubmit, resultTitle, recheckStep, retryKind, canEditRolesAfterReject, showNoImpact,
  setRow, rolesConfirm, rolesConfirmNotify, confirmOpen, confirmPreview, confirmUnavailable, confirmNotify,
  confirmFootnote, proceedConfirm, cancelConfirm, submit, retry, recheck,
} = useGroupSetupSubmit({
  props, form, roleDraft, matchTrimmed, dictEntry, managementNames, canAssign,
  nameError, phase, step, running, gateBusy, editorBindings,
})

// 焦點：步驟、階段切換或確認框關閉後，持有焦點的按鈕可能已被移除，焦點要留在抽屜內
const focusAnchor = ref(null)
const focusIntoDrawer = async () => {
  await nextTick()
  focusAnchor.value?.focus({ preventScroll: true })
}
watch([step, phase, running], () => {
  if (visible.value) focusIntoDrawer()
})
const drawerHasFocus = () => {
  const a = document.activeElement
  return Boolean(a && a !== document.body && a.closest('[data-test="group-setup-drawer"]'))
}
watch(
  () => [confirmOpen.value, rolesConfirm.open],
  (now, prev) => {
    if (!visible.value || !(prev[0] || prev[1]) || now[0] || now[1]) return
    // 確認框自己的焦點歸還完成後，若仍不在抽屜內才拉回
    setTimeout(() => {
      if (visible.value && !drawerHasFocus()) focusIntoDrawer()
    }, 50)
  }
)

// 回第 2 步改選：讀回的指派與送出的不同時，以讀回的指派為編輯器的基底
const editRoles = () => {
  if (run.rows[1].state === 'differs') {
    editorBindings.value = run.readBack
    preselectIds.value = []
    editorKey.value += 1
  }
  setRow(1, 'notRun')
  setRow(2, 'notRun')
  phase.value = 'form'
  step.value = 2
}

const reset = () => {
  phase.value = 'form'
  step.value = 1
  form.name = ''
  form.description = ''
  form.matchValue = ''
  form.note = ''
  nameError.value = ''
  running.value = false
  Object.assign(run, newRunState())
  editorBindings.value = []
  roleDraft.value = { roleIds: [], roleNodes: {} }
  rolesPreview.cancel()
  editorKey.value += 1
}

/** 開啟抽屜。matchValue、note 為從規則對話框帶入的外部群組與顯示名稱；entry 為入口來源 */
const open = ({ matchValue = '', note = '', entry: from = '' } = {}) => {
  reset()
  entry.value = from
  const value = String(matchValue || '').trim()
  carried.value = value ? { matchValue: value, note: note || '' } : null
  form.matchValue = value
  form.note = value ? note || '' : ''
  preselectIds.value = []
  if (ENTRIES_PRESELECT.includes(from)) {
    // 預選內建資產管理員：依內建識別判定，不看顯示名稱；在角色選單中停用時不預選
    const def = props.definitions.find((d) => d.builtin_key === 'asset_admin')
    const selectable =
      def && def.assignment_state !== 'protected' && def.assignment_state !== 'not_open' && def.group_bindable !== false
    if (selectable) preselectIds.value = [def.id]
  }
  visible.value = true
}

const close = () => {
  if (running.value) return
  visible.value = false
  emit('closed')
}
const beforeClose = () => {
  close()
}

defineExpose({ open })
</script>

<style scoped>
.steps-head {
  display: flex;
  gap: var(--ot-space-md);
  flex-wrap: wrap;
  list-style: none;
  margin: 0 0 var(--ot-space-md);
  padding: 0;
  color: var(--ot-text-secondary);
}
.steps-head li {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
}
.steps-head li.current {
  color: var(--ot-text-primary);
  font-weight: 600;
}
.steps-head li.finished {
  color: var(--ot-text-primary);
}
.step-no {
  display: inline-block;
  min-width: 1.5em;
  font-weight: 600;
}
.step-check {
  color: var(--ot-success, var(--el-color-success));
}
.note-box,
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
.field-error {
  color: var(--ot-danger, var(--el-color-danger));
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
  margin-top: var(--ot-space-xs);
}
.carried-value {
  width: 100%;
  overflow-wrap: anywhere;
  font-family: var(--ot-font-mono, monospace);
  font-size: var(--ot-font-size-sm);
}
.task-list {
  list-style: none;
  margin: 0 0 var(--ot-space-sm);
  padding: 0;
  display: grid;
  gap: var(--ot-space-sm);
}
.focus-anchor:focus {
  outline: none;
}
.drawer-footer {
  display: flex;
  justify-content: flex-end;
  gap: var(--ot-space-sm);
  flex-wrap: wrap;
}
</style>
