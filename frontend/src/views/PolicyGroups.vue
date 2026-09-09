<template>
  <div
    v-loading="loading"
    class="policy-groups"
  >
    <PageHeader
      :title="$t('menu.policyGroups')"
      :description="$t('policyGroups.headerDesc')"
    >
      <template #actions>
        <el-button
          :loading="loading"
          data-test="policy-groups-refresh"
          @click="load()"
        >
          {{ $t('common.refresh') }}
        </el-button>
        <el-button
          type="primary"
          class="create-group"
          @click="openCreate"
        >
          {{ $t('policyGroups.create') }}
        </el-button>
      </template>
    </PageHeader>

    <div
      v-if="groups.length === 0"
      class="panel"
    >
      <EmptyState :title="$t('policyGroups.emptyGroups')" />
    </div>

    <div
      v-else
      class="card-row"
    >
      <div
        v-for="group in groups"
        :key="group.code"
        class="group-card"
        :class="{ active: group.code === activeCode }"
        @click="activeCode = group.code"
      >
        <div class="card-head">
          <span class="card-name">{{ group.name }}</span>
          <el-tag
            size="small"
            :type="group.source === 'custom' ? 'warning' : 'info'"
          >
            {{ sourceLabel(group.source) }}
          </el-tag>
        </div>
        <div class="card-meta">
          <span v-if="group.version">{{ $t('policyGroups.versionLabel', { version: group.version }) }}</span>
          <span v-if="group.locale">{{ $t('policyGroups.localeLabel', { locale: group.locale }) }}</span>
          <span>{{ $t('policyGroups.clauseCount', { n: clauseCountOf(group.code) }) }}</span>
        </div>
        <div
          class="card-actions"
          @click.stop
        >
          <el-switch
            :model-value="group.enabled"
            :active-text="$t('policyGroups.enabledLabel')"
            @change="(value) => toggleEnabled(group, value)"
          />
          <template v-if="group.source === 'custom'">
            <el-button
              text
              class="group-rename"
              @click="openRename(group)"
            >
              {{ $t('policyGroups.rename') }}
            </el-button>
            <el-button
              text
              type="danger"
              class="group-delete"
              @click="removeGroup(group)"
            >
              {{ $t('policyGroups.remove') }}
            </el-button>
          </template>
        </div>
      </div>
    </div>

    <div
      v-if="activeGroup.code"
      class="panel"
    >
      <div class="panel-head">
        <span class="panel-title">
          {{ $t('policyGroups.clausesTitle', { name: activeGroup.name }) }}
        </span>
        <el-button
          v-if="isCustomGroup"
          class="add-clause"
          @click="openClause(null)"
        >
          {{ $t('policyGroups.addClause') }}
        </el-button>
      </div>

      <p class="panel-hint">
        {{ isCustomGroup ? $t('policyGroups.customHint') : $t('policyGroups.builtinHint') }}
      </p>

      <el-table
        :data="activeClauses"
        stripe
        style="width: 100%"
      >
        <el-table-column
          :label="$t('policyGroups.colClauseNo')"
          width="140"
        >
          <template #default="{ row }">
            <span class="clause-no">{{ row.clause_no }}</span>
            <el-tag
              v-if="row.removed_in_version"
              size="small"
              type="info"
              :title="$t('policyGroups.removedHint', { version: row.removed_in_version })"
            >
              {{ $t('policyGroups.removedTag') }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column
          :label="$t('policyGroups.colTitle')"
          min-width="200"
        >
          <template #default="{ row }">
            <span class="clause-title">{{ clauseTitle(row) }}</span>
          </template>
        </el-table-column>

        <el-table-column
          :label="$t('policyGroups.colKind')"
          width="130"
        >
          <template #default="{ row }">
            {{ kindLabel(row.kind) }}
          </template>
        </el-table-column>

        <el-table-column
          :label="$t('policyGroups.colKeys')"
          min-width="180"
        >
          <template #default="{ row }">
            {{ keysText(row) }}
          </template>
        </el-table-column>

        <el-table-column
          :label="$t('policyGroups.colExpectation')"
          min-width="180"
        >
          <template #default="{ row }">
            {{ expectationsText(row) }}
          </template>
        </el-table-column>

        <el-table-column
          :label="$t('policyGroups.colNote')"
          min-width="160"
        >
          <template #default="{ row }">
            <span class="note-text">{{ noteOf(row) }}</span>
            <span
              v-if="row.annotation && row.annotation.confirmed_at"
              class="note-confirmed"
            >
              {{ $t('complianceMap.confirmed', {
                who: row.annotation.confirmed_by,
                when: formatDateTime(row.annotation.confirmed_at),
              }) }}
            </span>
          </template>
        </el-table-column>

        <el-table-column
          :label="$t('policyGroups.colActions')"
          width="230"
        >
          <template #default="{ row }">
            <el-button
              text
              class="clause-note"
              @click="openNote(row)"
            >
              {{ $t('policyGroups.noteAction') }}
            </el-button>
            <el-button
              v-if="canConfirm(row)"
              text
              class="clause-confirm"
              @click="openConfirm(row)"
            >
              {{ $t('policyGroups.confirmAction') }}
            </el-button>
            <el-button
              v-if="isCustomGroup"
              text
              class="clause-edit"
              @click="openClause(row)"
            >
              {{ $t('policyGroups.editAction') }}
            </el-button>
            <el-button
              v-if="isCustomGroup"
              text
              type="danger"
              class="clause-delete"
              @click="removeClause(row)"
            >
              {{ $t('policyGroups.deleteAction') }}
            </el-button>
          </template>
        </el-table-column>

        <template #empty>
          <EmptyState
            :title="$t('policyGroups.emptyClauses')"
            :hint="isCustomGroup ? $t('policyGroups.emptyClausesHint') : ''"
          />
        </template>
      </el-table>
    </div>

    <ClauseDialog
      v-model="clauseDialogVisible"
      :group-code="activeCode"
      :clause="editingClause"
      :policies="policies"
      @saved="onSaved"
    />

    <el-dialog
      v-model="noteVisible"
      :title="$t('policyGroups.noteDialogTitle')"
      width="520px"
    >
      <p class="dialog-hint">
        {{ $t('policyGroups.noteDialogHint') }}
      </p>
      <el-input
        v-model="noteForm.note"
        type="textarea"
        :rows="3"
        :placeholder="$t('policyGroups.notePlaceholder')"
      />
      <template #footer>
        <el-button @click="noteVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          @click="saveNote"
        >
          {{ $t('common.save') }}
        </el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="confirmVisible"
      :title="$t('policyGroups.confirmDialogTitle')"
      width="520px"
    >
      <p class="dialog-hint">
        {{ $t('policyGroups.confirmDialogHint') }}
      </p>
      <p
        v-if="confirmForm.previous"
        class="dialog-hint"
      >
        {{ confirmForm.previous }}
      </p>
      <el-input
        v-model="confirmForm.note"
        type="textarea"
        :rows="3"
        :placeholder="$t('policyGroups.confirmPlaceholder')"
      />
      <p
        v-if="confirmError"
        class="dialog-error"
      >
        {{ confirmError }}
      </p>
      <template #footer>
        <el-button @click="confirmVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          @click="saveConfirm"
        >
          {{ $t('common.confirm') }}
        </el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="createVisible"
      :title="isRenaming
        ? $t('policyGroups.renameDialogTitle')
        : $t('policyGroups.createDialogTitle')"
      width="520px"
    >
      <el-form label-position="top">
        <el-form-item
          v-if="!isRenaming"
          :label="$t('policyGroups.codeField')"
        >
          <el-input
            v-model="createForm.code"
            maxlength="64"
          />
          <div class="dialog-hint">
            {{ $t('policyGroups.codeHint') }}
          </div>
        </el-form-item>
        <el-form-item :label="$t('policyGroups.nameField')">
          <el-input
            v-model="createForm.name"
            maxlength="200"
          />
        </el-form-item>
        <el-form-item
          v-if="!isRenaming"
          :label="$t('policyGroups.localeField')"
        >
          <el-select v-model="createForm.locale">
            <el-option
              v-for="option in LOCALE_OPTIONS"
              :key="option"
              :label="option"
              :value="option"
            />
          </el-select>
          <div class="dialog-hint">
            {{ $t('policyGroups.localeHint') }}
          </div>
        </el-form-item>
      </el-form>
      <p
        v-if="createError"
        class="dialog-error"
      >
        {{ createError }}
      </p>
      <template #footer>
        <el-button @click="createVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          @click="saveCreate"
        >
          {{ $t('common.save') }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { useI18n } from 'vue-i18n'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import ClauseDialog from '@/components/ClauseDialog.vue'
import { getComplianceSnapshot } from '@/api/compliance'
import { getSecurityPolicies } from '@/api/securityPolicies'
import {
  confirmClause,
  createPolicyGroup,
  deletePolicyClause,
  deletePolicyGroup,
  renamePolicyGroup,
  setPolicyGroupEnabled,
  upsertClauseAnnotation,
} from '@/api/policyGroups'
import { resolveApiError } from '@/api/error'
import { confirmDestructive } from '@/utils/confirm'
import { formatDateTime } from '@/utils/format'
import { clauseTitle, expectationText, settingLabel } from '@/utils/policyClauseText'

// 政策組管理頁：政策組、條文、備註與人工確認的**唯一寫入入口**。
//
// 內建組的條文不開放編輯：它隨產品版本 upsert，改了下次升級就被蓋回去，而機構
// 會以為自己改過。機構要的差異寫成自建組的條文——那才是會被判定看見的東西。
//
// 讀取走判定結果那一支：它一次回組、全部條文與掛在條文上的備註，卡片上的條文數
// 與下方的條文表因此來自同一個時點；分兩支讀會讓兩處在有人同時寫入時對不起來。

const LOCALE_OPTIONS = ['zh-TW', 'en-US', 'ja-JP']

const { t } = useI18n()

const loading = ref(false)
const groups = ref([])
const clauses = ref([])
const policies = ref([])
const activeCode = ref('')

const clauseDialogVisible = ref(false)
const editingClause = ref(null)

const noteVisible = ref(false)
const noteForm = reactive({ clause: null, note: '' })

const confirmVisible = ref(false)
const confirmForm = reactive({ clause: null, note: '', previous: '' })
const confirmError = ref('')

const createVisible = ref(false)
const isRenaming = ref(false)
const createForm = reactive({ code: '', name: '', locale: 'zh-TW' })
const createError = ref('')

const activeGroup = computed(
  () => groups.value.find((g) => g.code === activeCode.value) || {}
)

const isCustomGroup = computed(() => activeGroup.value.source === 'custom')

const activeClauses = computed(() =>
  clauses.value.filter((c) => c.group_code === activeCode.value)
)

const clauseCountOf = (code) =>
  clauses.value.filter((c) => c.group_code === code).length

const sourceLabel = (source) =>
  source === 'custom'
    ? t('policyGroups.sourceCustom')
    : t('policyGroups.sourceBuiltin')

const kindLabel = (kind) => {
  if (kind === 'self_attested') return t('policyGroups.kindSelfAttested')
  if (kind === 'builtin_protection') return t('policyGroups.kindBuiltinProtection')
  return t('policyGroups.kindSetting')
}

const keysText = (clause) => {
  const controls = clause.controls || []
  if (controls.length === 0) return t('policyGroups.noneKeys')
  return controls.map((c) => settingLabel(c.policy_key)).join('、')
}

// 要求值的單位與零值語義取自設定清單：判定結果那一支在本頁沒有逐條的對應，
// 而「至少 10」在同一張表裡可能是天、秒或字元。取不到清單時只少單位，不猜
const metaOf = (key) => {
  const policy = policies.value.find((p) => p.key === key)
  if (!policy) return {}
  return {
    unit_key: policy.unit_key,
    unit: policy.unit,
    zero_disables: policy.zero_disables,
  }
}

const expectationsText = (clause) => {
  const controls = clause.controls || []
  if (controls.length === 0) return t('policyGroups.noneKeys')
  return controls.map((c) => expectationText(c, metaOf(c.policy_key))).join('、')
}

const noteOf = (clause) => clause.annotation?.note || ''

// 可確認的只有以參考值呈現的條文：規範沒給固定值，由機構自己認定怎麼算數
const canConfirm = (clause) => (clause.controls || []).some((c) => c.reference_only)

const load = async () => {
  loading.value = true
  try {
    const res = await getComplianceSnapshot()
    groups.value = res.groups || []
    clauses.value = res.clauses || []
    if (!groups.value.some((g) => g.code === activeCode.value)) {
      activeCode.value = groups.value[0]?.code || ''
    }
  } catch (error) {
    console.error('讀取政策組失敗:', error)
  } finally {
    loading.value = false
  }
}

const loadPolicies = async () => {
  try {
    const res = await getSecurityPolicies()
    policies.value = res.data || []
  } catch (error) {
    // 取不到只影響條文表單的鍵清單，不影響既有條文的呈現
    console.error('取得設定清單失敗:', error)
  }
}

const toggleEnabled = async (group, value) => {
  try {
    await setPolicyGroupEnabled(group.code, value === true)
    ElMessage.success(t('policyGroups.saved'))
    await load()
  } catch (error) {
    console.error('切換政策組生效狀態失敗:', error)
    await load()
  }
}

const openClause = (clause) => {
  editingClause.value = clause
  clauseDialogVisible.value = true
}

const onSaved = async () => {
  ElMessage.success(t('policyGroups.saved'))
  await load()
}

const removeClause = async (clause) => {
  try {
    await confirmDestructive(
      t('policyGroups.deleteClauseMessage', { no: clause.clause_no }),
      t('policyGroups.deleteClauseTitle')
    )
  } catch {
    return
  }
  try {
    await deletePolicyClause(clause.group_code, clause.clause_no)
    ElMessage.success(t('policyGroups.deleted'))
    await load()
  } catch (error) {
    console.error('刪除條文失敗:', error)
  }
}

const removeGroup = async (group) => {
  try {
    await confirmDestructive(
      t('policyGroups.deleteMessage', { name: group.name }),
      t('policyGroups.deleteTitle')
    )
  } catch {
    return
  }
  try {
    await deletePolicyGroup(group.code)
    ElMessage.success(t('policyGroups.deleted'))
    await load()
  } catch (error) {
    console.error('刪除政策組失敗:', error)
  }
}

const openNote = (clause) => {
  noteForm.clause = clause
  noteForm.note = clause.annotation?.note || ''
  noteVisible.value = true
}

const saveNote = async () => {
  const clause = noteForm.clause
  if (!clause) return
  try {
    await upsertClauseAnnotation(clause.group_code, clause.clause_no, noteForm.note)
    noteVisible.value = false
    ElMessage.success(t('policyGroups.saved'))
    await load()
  } catch (error) {
    console.error('寫入備註失敗:', error)
  }
}

const openConfirm = (clause) => {
  confirmForm.clause = clause
  confirmForm.note = ''
  confirmForm.previous = clause.annotation?.confirmed_at
    ? t('policyGroups.confirmAgainHint', {
      who: clause.annotation.confirmed_by,
      when: formatDateTime(clause.annotation.confirmed_at),
    })
    : ''
  confirmError.value = ''
  confirmVisible.value = true
}

const saveConfirm = async () => {
  const clause = confirmForm.clause
  if (!clause) return
  if (!confirmForm.note.trim()) {
    confirmError.value = t('policyGroups.confirmRequired')
    return
  }
  try {
    await confirmClause(clause.group_code, clause.clause_no, confirmForm.note.trim())
    confirmVisible.value = false
    ElMessage.success(t('policyGroups.saved'))
    await load()
  } catch (error) {
    console.error('人工確認失敗:', error)
  }
}

const openCreate = () => {
  isRenaming.value = false
  createForm.code = ''
  createForm.name = ''
  createForm.locale = 'zh-TW'
  createError.value = ''
  createVisible.value = true
}

const openRename = (group) => {
  isRenaming.value = true
  createForm.code = group.code
  createForm.name = group.name
  createError.value = ''
  createVisible.value = true
}

const saveCreate = async () => {
  createError.value = ''
  if (!isRenaming.value && !createForm.code.trim()) {
    createError.value = t('policyGroups.requiredCode')
    return
  }
  if (!createForm.name.trim()) {
    createError.value = t('policyGroups.requiredName')
    return
  }
  try {
    if (isRenaming.value) {
      await renamePolicyGroup(createForm.code, createForm.name.trim(), {
        skipErrorToast: true,
      })
    } else {
      await createPolicyGroup(
        {
          code: createForm.code.trim(),
          name: createForm.name.trim(),
          locale: createForm.locale,
        },
        { skipErrorToast: true }
      )
      activeCode.value = createForm.code.trim()
    }
    createVisible.value = false
    ElMessage.success(t('policyGroups.saved'))
    await load()
  } catch (error) {
    createError.value = resolveApiError(error?.response?.data, error?.response?.status)
  }
}

onMounted(async () => {
  await load()
  await loadPolicies()
})

defineExpose({
  activeCode,
  createForm,
  noteForm,
  confirmForm,
  toggleEnabled,
  removeGroup,
  removeClause,
  openCreate,
  saveCreate,
  openRename,
  openNote,
  saveNote,
  openConfirm,
  saveConfirm,
  openClause,
})
</script>

<style scoped>
.card-row {
  display: flex;
  flex-wrap: wrap;
  gap: var(--ot-space-md);
  margin-bottom: var(--ot-space-md);
}

.group-card {
  flex: 1 1 260px;
  max-width: 360px;
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  cursor: pointer;
}

.group-card.active {
  border-color: var(--ot-primary);
  background-color: var(--ot-primary-dim);
}

.card-head {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-xs);
}

.card-name {
  font-size: var(--ot-font-size-md);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.card-meta {
  display: flex;
  flex-wrap: wrap;
  gap: var(--ot-space-sm);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
  margin-bottom: var(--ot-space-sm);
}

.card-actions {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
}

.panel {
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: var(--ot-space-xs);
}

.panel-title {
  font-size: var(--ot-font-size-md);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.panel-hint {
  margin: 0 0 var(--ot-space-md);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.clause-no {
  margin-right: var(--ot-space-xs);
  color: var(--ot-text-primary);
}

.note-text {
  color: var(--ot-text-primary);
}

.note-confirmed {
  display: block;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.dialog-hint {
  margin: 0 0 var(--ot-space-sm);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
  line-height: 1.6;
}

.dialog-error {
  margin: var(--ot-space-sm) 0 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-danger);
}
</style>
