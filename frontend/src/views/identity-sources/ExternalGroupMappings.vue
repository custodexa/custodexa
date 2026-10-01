<template>
  <div class="external-mappings">
    <PageHeader
      :title="$t('identityGroupMappings.title')"
      :description="$t('identityGroupMappings.subtitle')"
    >
      <template #actions>
        <router-link :to="`/identity-sources/${sourceType}/${sourceId}`">
          <el-button>{{ $t('identityGroupMappings.backToSource') }}</el-button>
        </router-link>
      </template>
    </PageHeader>

    <div class="source-summary">
      <strong>{{ source?.name || sourceId }}</strong>
      <el-tag size="small">
        {{ sourceTypeLabel }}
      </el-tag>
      <el-tag
        size="small"
        :type="source?.enabled === true ? 'success' : 'info'"
      >
        {{ source?.enabled === true ? $t('common.enabled') : $t('common.disabled') }}
      </el-tag>
      <span>{{ $t('identityGroupMappings.verifiedSourceHint') }}</span>
    </div>

    <el-alert
      v-if="source && source.group_attribute_configured === false"
      type="warning"
      :closable="false"
      :title="$t('identityGroupMappings.sourceAttrMissingHint')"
    />
    <p class="observation-rule">
      {{ $t('identityGroupMappings.unknownObservationRule') }}
    </p>

    <el-tabs
      v-model="tab"
      class="mapping-tabs"
      style="--el-transition-duration: 0s"
    >
      <el-tab-pane
        :label="$t('identityGroupMappings.tabs.roles')"
        name="roles"
      />
      <el-tab-pane
        :label="$t('identityGroupMappings.tabs.userGroups')"
        name="userGroups"
      />
    </el-tabs>

    <div class="table-toolbar">
      <el-select
        v-model="targetFilter"
        clearable
        :placeholder="$t('identityGroupMappings.filterTarget')"
        style="width: 240px"
      >
        <el-option
          v-for="item in targetOptions"
          :key="item.value"
          :label="item.label"
          :value="item.value"
        />
      </el-select>
      <el-button @click="loadAll">
        {{ $t('common.refresh') }}
      </el-button>
      <el-button
        type="primary"
        @click="openCreate"
      >
        {{ $t('identityGroupMappings.add') }}
      </el-button>
    </div>

    <el-table
      v-loading="loading"
      :data="visibleRows"
      stripe
    >
      <el-table-column
        :label="$t('identityGroupMappings.columns.externalGroup')"
        min-width="260"
      >
        <template #default="{ row }">
          <div
            class="group-primary"
            :class="{ 'group-value-collapsed': !row.note && !expandedValues.has(row.id) }"
          >
            {{ row.note || row.match_value }}
          </div>
          <div
            v-if="row.note"
            class="group-value"
            :class="{ 'group-value-collapsed': !expandedValues.has(row.id) }"
          >
            {{ row.match_value }}
          </div>
          <el-button
            data-test="copy-group-value"
            size="small"
            link
            @click="copyGroupValue(row.match_value)"
          >
            {{ $t('identityGroupMappings.copyIdentifier') }}
          </el-button>
          <el-button
            data-test="expand-group-value"
            size="small"
            link
            @click="toggleGroupValue(row.id)"
          >
            {{ expandedValues.has(row.id) ? $t('identityGroupMappings.collapseIdentifier') : $t('identityGroupMappings.expandIdentifier') }}
          </el-button>
          <el-button
            size="small"
            link
            @click="openNote(row)"
          >
            {{ $t('identityGroupMappings.editNote') }}
          </el-button>
        </template>
      </el-table-column>
      <el-table-column
        :label="tab === 'roles' ? $t('identityGroupMappings.columns.targetRole') : $t('identityGroupMappings.columns.targetUserGroup')"
        min-width="180"
      >
        <template #default="{ row }">
          {{ tab === 'roles' ? row.role : row.user_group_name }}
        </template>
      </el-table-column>
      <el-table-column
        v-if="tab === 'userGroups'"
        :label="$t('identityGroupMappings.columns.usage')"
        min-width="210"
      >
        <template #default="{ row }">
          {{ usageText(row.usage) }}
        </template>
      </el-table-column>
      <el-table-column
        :label="$t('common.status')"
        width="95"
      >
        <template #default="{ row }">
          {{ row.enabled ? $t('common.enabled') : $t('common.disabled') }}
        </template>
      </el-table-column>
      <el-table-column
        :label="$t('identityGroupMappings.columns.createdBy')"
        prop="created_by"
        width="120"
      />
      <el-table-column
        :label="$t('identityGroupMappings.columns.updatedAt')"
        width="190"
      >
        <template #default="{ row }">
          {{ row.updated_at ? new Date(row.updated_at).toLocaleString() : '' }}
        </template>
      </el-table-column>
      <el-table-column
        :label="$t('common.actions')"
        width="220"
      >
        <template #default="{ row }">
          <el-button
            size="small"
            link
            @click="openEdit(row)"
          >
            {{ $t('common.edit') }}
          </el-button>
          <el-button
            size="small"
            link
            @click="toggle(row)"
          >
            {{ row.enabled ? $t('identityGroupMappings.disable') : $t('identityGroupMappings.enable') }}
          </el-button>
          <el-button
            size="small"
            type="danger"
            link
            @click="remove(row)"
          >
            {{ $t('common.delete') }}
          </el-button>
        </template>
      </el-table-column>
      <template #empty>
        {{ tab === 'roles' ? $t('identityGroupMappings.empty.roles') : $t('identityGroupMappings.empty.userGroups') }}
      </template>
    </el-table>

    <el-dialog
      v-model="dialogOpen"
      :title="editing ? $t('identityGroupMappings.edit') : $t('identityGroupMappings.add')"
      width="560px"
      :close-on-click-modal="false"
    >
      <el-form label-position="top">
        <el-form-item
          :label="$t('identityGroupMappings.columns.externalGroup')"
          required
        >
          <el-autocomplete
            v-model="draft.match_value"
            :fetch-suggestions="suggestExternalGroups"
            value-key="value"
            style="width: 100%"
            maxlength="500"
            @select="selectExternalGroup"
          />
        </el-form-item>
        <el-form-item :label="$t('identityGroupMappings.fields.note')">
          <el-input
            v-model="draft.note"
            data-test="rule-note-input"
            maxlength="200"
          />
          <div
            v-if="matchingExternalGroup"
            class="field-hint"
          >
            {{ $t('identityGroupMappings.noteSharedHint') }}
          </div>
        </el-form-item>
        <el-form-item
          :label="tab === 'roles' ? $t('identityGroupMappings.columns.targetRole') : $t('identityGroupMappings.columns.targetUserGroup')"
          required
        >
          <el-select
            v-if="tab === 'roles'"
            v-model="draft.role"
            style="width: 100%"
          >
            <el-option
              v-for="role in roles"
              :key="role.name"
              :label="role.name"
              :value="role.name"
            />
          </el-select>
          <el-select
            v-else
            v-model="draft.user_group_id"
            filterable
            style="width: 100%"
            @change="loadUsage"
          >
            <el-option
              v-for="group in userGroups"
              :key="group.id"
              :label="group.name"
              :value="group.id"
            />
          </el-select>
        </el-form-item>
        <div
          v-if="tab === 'userGroups' && draft.user_group_id"
          class="usage-box"
        >
          {{ $t('identityGroupMappings.currentUsage', usage) }}
        </div>
        <el-checkbox
          v-if="requiresUsageAck"
          v-model="usageConfirmed"
        >
          {{ $t('identityGroupMappings.confirmUsage') }}
        </el-checkbox>
        <el-form-item :label="$t('common.status')">
          <el-switch v-model="draft.enabled" />
        </el-form-item>
        <el-alert
          v-if="editing && (draft.match_value !== editing.match_value || targetChanged)"
          type="warning"
          :closable="false"
          :title="$t('identityGroupMappings.editIdentityHint')"
        />
      </el-form>
      <template #footer>
        <el-button @click="dialogOpen = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="busy"
          :disabled="!canSave"
          @click="save"
        >
          {{ $t('common.save') }}
        </el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="noteOpen"
      :title="$t('identityGroupMappings.editNote')"
      width="480px"
    >
      <el-input
        v-model="noteDraft"
        maxlength="200"
        show-word-limit
      />
      <div class="field-hint">
        {{ $t('identityGroupMappings.noteSharedHint') }}
      </div>
      <template #footer>
        <el-button @click="noteOpen = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="busy"
          @click="saveNote"
        >
          {{ $t('common.save') }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import PageHeader from '@/components/PageHeader.vue'
import { t } from '@/i18n'
import { getRoleList } from '@/api/user'
import { getUserGroups } from '@/api/userGroups'
import { errorCode, getIdentitySources, getRoleMappings, createRoleMapping, updateRoleMapping, deleteRoleMapping, getUserGroupMappings, getUserGroupMappingUsage, createUserGroupMapping, updateUserGroupMapping, deleteUserGroupMapping, getExternalGroups, updateExternalGroupNote } from '@/api/identitySources'
import { confirmWarnings } from '@/utils/mappingRiskGate'

const route = useRoute()
const sourceType = computed(() => String(route.params.type || ''))
const sourceId = computed(() => String(route.params.id || ''))
const sourceTypeLabel = computed(() => t(`identitySources.typeLabel.${sourceType.value}`))
const source = ref(null)
const roles = ref([])
const userGroups = ref([])
const roleRows = ref([])
const groupRows = ref([])
const externalGroups = ref([])
const tab = ref('roles')
const targetFilter = ref('')
const loading = ref(false)
const busy = ref(false)
const dialogOpen = ref(false)
const noteOpen = ref(false)
const editing = ref(null)
const noteRow = ref(null)
const noteDraft = ref('')
const expandedValues = ref(new Set())
const draft = ref({ match_value: '', note: '', role: '', user_group_id: null, enabled: true })
const usage = ref({ asset_authorizations: 0, approver_scopes: 0, requester_scopes: 0 })
const usageConfirmed = ref(false)

const rows = computed(() => tab.value === 'roles' ? roleRows.value : groupRows.value)
const targetOptions = computed(() => {
  const options = rows.value.map(row => tab.value === 'roles' ? { value: row.role, label: row.role } : { value: row.user_group_id, label: row.user_group_name })
  return [...new Map(options.map(item => [item.value, item])).values()]
})
const visibleRows = computed(() => targetFilter.value ? rows.value.filter(row => (tab.value === 'roles' ? row.role : row.user_group_id) === targetFilter.value) : rows.value)
const hasUsage = computed(() => Object.values(usage.value).some(n => Number(n) > 0))
const targetChanged = computed(() => Boolean(editing.value && (tab.value === 'roles' ? draft.value.role !== editing.value.role : draft.value.user_group_id !== editing.value.user_group_id)))
const requiresUsageAck = computed(() => tab.value === 'userGroups' && hasUsage.value && (!editing.value || targetChanged.value))
const canSave = computed(() => draft.value.match_value.trim() && (tab.value === 'roles' ? draft.value.role : draft.value.user_group_id) && (!requiresUsageAck.value || usageConfirmed.value))
const matchingExternalGroup = computed(() => externalGroups.value.find(group => group.match_value === draft.value.match_value))
const suggestExternalGroups = (query, callback) => callback(externalGroups.value.filter(group => group.match_value.toLowerCase().includes(query.toLowerCase())).map(group => ({ value: group.match_value, note: group.note })))
const selectExternalGroup = (group) => { draft.value.note = group.note || '' }
const toggleGroupValue = id => {
  const next = new Set(expandedValues.value)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  expandedValues.value = next
}
const copyGroupValue = async value => {
  try {
    await navigator.clipboard.writeText(value)
    ElMessage.success(t('identityGroupMappings.identifierCopied'))
  } catch { ElMessage.error(t('identityGroupMappings.copyFailed')) }
}
const usageText = (value = {}) => t('identityGroupMappings.currentUsage', { asset_authorizations: value.asset_authorizations || 0, approver_scopes: value.approver_scopes || 0, requester_scopes: value.requester_scopes || 0 })

const loadAll = async () => {
  loading.value = true
  try {
    const [sources, roleResult, groupResult, roleList, groupList, dictionary] = await Promise.all([
      getIdentitySources(), getRoleMappings(sourceType.value, sourceId.value), getUserGroupMappings(sourceType.value, sourceId.value), getRoleList(), getUserGroups(), getExternalGroups(sourceType.value, sourceId.value),
    ])
    source.value = (sources.data || []).find(item => item.type === sourceType.value && String(item.id) === sourceId.value) || null
    roleRows.value = roleResult.data || []
    groupRows.value = groupResult.data || []
    externalGroups.value = dictionary.data || []
    roles.value = roleList.data || []
    userGroups.value = groupList.data || []
  } catch (error) {
    ElMessage.error(t('identityGroupMappings.loadFailed'))
    console.error('identity_group_mappings_load_failed', error)
  } finally { loading.value = false }
}

const loadUsage = async () => {
  usage.value = { asset_authorizations: 0, approver_scopes: 0, requester_scopes: 0 }
  usageConfirmed.value = false
  if (!draft.value.user_group_id) return
  try {
    const result = await getUserGroupMappingUsage(sourceType.value, sourceId.value, draft.value.user_group_id)
    usage.value = result.data || usage.value
  } catch (error) {
    ElMessage.error(t('identityGroupMappings.loadFailed'))
    console.error('identity_group_mapping_usage_failed', error)
  }
}
const openCreate = () => { editing.value = null; draft.value = { match_value: '', note: '', role: '', user_group_id: null, enabled: true }; usageConfirmed.value = false; usage.value = { asset_authorizations: 0, approver_scopes: 0, requester_scopes: 0 }; dialogOpen.value = true }
const openEdit = async (row) => { editing.value = row; draft.value = { match_value: row.match_value, note: row.note || '', role: row.role || '', user_group_id: row.user_group_id || null, enabled: row.enabled }; dialogOpen.value = true; if (tab.value === 'userGroups') await loadUsage() }
const openNote = (row) => { noteRow.value = row; noteDraft.value = row.note || ''; noteOpen.value = true }

const persist = async (payload) => {
  const type = sourceType.value; const id = sourceId.value
  if (tab.value === 'roles') return editing.value ? updateRoleMapping(type, id, editing.value.id, payload) : createRoleMapping(type, id, payload)
  return editing.value ? updateUserGroupMapping(type, id, editing.value.id, payload) : createUserGroupMapping(type, id, payload)
}
const save = async () => {
  if (!canSave.value) return
  busy.value = true
  let acknowledged = usageConfirmed.value
  let sourceConfigAcknowledged = false
  try {
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const payload = { match_value: draft.value.match_value.trim(), enabled: draft.value.enabled, risk_acknowledged: acknowledged, source_config_acknowledged: sourceConfigAcknowledged }
        if (tab.value === 'roles') payload.role = draft.value.role
        else payload.user_group_id = draft.value.user_group_id
        const existingGroup = matchingExternalGroup.value
        if (!existingGroup) payload.note = draft.value.note
        await persist(payload)
        dialogOpen.value = false
        let noteFailed = false
        if (existingGroup && draft.value.note !== (existingGroup.note || '')) {
          try {
            await updateExternalGroupNote(sourceType.value, sourceId.value, existingGroup.id, draft.value.note)
          } catch (error) {
            noteFailed = true
            console.error('external_group_note_update_failed', error)
          }
        }
        if (noteFailed) ElMessage.error(t('identityGroupMappings.ruleSavedNoteFailed'))
        else ElMessage.success(t('identityGroupMappings.saved'))
        await loadAll()
        return
      } catch (error) {
        const code = errorCode(error)
        if (code === 'MAPPING_ACK_REQUIRED' && !sourceConfigAcknowledged) {
          const meta = error.response?.data?.meta || error.response?.data?.error?.meta || {}
          const warnings = (meta.warnings || []).map(item => item.code)
          if (!(await confirmWarnings(warnings))) return
          sourceConfigAcknowledged = true
          if (tab.value === 'roles') acknowledged = true
          continue
        }
        if (code === 'MAPPING_USAGE_ACK_REQUIRED' && !acknowledged) {
          const meta = error.response?.data?.meta || error.response?.data?.error?.meta || {}
          usage.value = meta.usage || usage.value
          usageConfirmed.value = false
          return
        }
        throw error
      }
    }
  } catch (error) { ElMessage.error(t('identityGroupMappings.saveFailed')); console.error('identity_group_mapping_save_failed', error) }
  finally { busy.value = false }
}

const confirmRevocation = async (row, action) => {
  const affected = Number(row.affected_user_count || 0)
  try { await ElMessageBox.confirm(t('identityGroupMappings.revokeConfirm', { action, count: affected, roles: row.effective_role_loss_count || 0, members: row.effective_member_loss_count || 0 }), t('identityGroupMappings.confirmTitle'), { type: 'warning' }); return true }
  catch { return false }
}
const toggle = async (row) => {
  if (row.enabled && !(await confirmRevocation(row, t('identityGroupMappings.disable')))) return
  const payload = { match_value: row.match_value, enabled: !row.enabled, risk_acknowledged: false, source_config_acknowledged: false }
  if (tab.value === 'roles') payload.role = row.role
  else payload.user_group_id = row.user_group_id
  const send = () => tab.value === 'roles' ? updateRoleMapping(sourceType.value, sourceId.value, row.id, { ...payload }) : updateUserGroupMapping(sourceType.value, sourceId.value, row.id, { ...payload })
  try {
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        await send()
        await loadAll()
        return
      } catch (error) {
        const code = errorCode(error)
        const meta = error.response?.data?.meta || error.response?.data?.error?.meta || {}
        if (code === 'MAPPING_ACK_REQUIRED' && !payload.source_config_acknowledged) {
          if (!(await confirmWarnings((meta.warnings || []).map(item => item.code)))) return
          payload.risk_acknowledged = true
          payload.source_config_acknowledged = true
          continue
        }
        if (code === 'MAPPING_USAGE_ACK_REQUIRED' && !payload.risk_acknowledged) {
          try {
            await ElMessageBox.confirm(`${usageText(meta.usage || {})} ${t('identityGroupMappings.confirmUsage')}`, t('identityGroupMappings.confirmTitle'), { type: 'warning' })
          } catch { return }
          payload.risk_acknowledged = true
          continue
        }
        throw error
      }
    }
    throw new Error('mapping confirmation retry exhausted')
  }
  catch (error) { ElMessage.error(t('identityGroupMappings.saveFailed')); console.error('identity_group_mapping_toggle_failed', error) }
}
const remove = async (row) => {
  if (!(await confirmRevocation(row, t('common.delete')))) return
  try { await (tab.value === 'roles' ? deleteRoleMapping(sourceType.value, sourceId.value, row.id) : deleteUserGroupMapping(sourceType.value, sourceId.value, row.id)); await loadAll() }
  catch (error) { ElMessage.error(t('identityGroupMappings.saveFailed')); console.error('identity_group_mapping_delete_failed', error) }
}
const saveNote = async () => {
  if (!noteRow.value) return
  busy.value = true
  try { await updateExternalGroupNote(sourceType.value, sourceId.value, noteRow.value.external_group_id, noteDraft.value); noteOpen.value = false; await loadAll() }
  catch (error) { ElMessage.error(t('identityGroupMappings.saveFailed')); console.error('external_group_note_update_failed', error) }
  finally { busy.value = false }
}

watch(tab, () => { targetFilter.value = '' })
watch(() => draft.value.match_value, () => {
  if (matchingExternalGroup.value) draft.value.note = matchingExternalGroup.value.note || ''
})
onMounted(loadAll)
</script>

<style scoped>
.external-mappings { display: grid; gap: var(--ot-space-md); }
.source-summary { display: flex; align-items: center; gap: var(--ot-space-sm); color: var(--ot-text-secondary); }
.observation-rule { margin: 0; color: var(--ot-text-secondary); font-size: var(--ot-font-size-sm); }
.table-toolbar { display: flex; justify-content: flex-end; gap: var(--ot-space-sm); }
.group-primary { font-weight: 600; overflow-wrap: anywhere; }
.group-value { color: var(--ot-text-secondary); font-family: var(--ot-font-mono, monospace); font-size: var(--ot-font-size-xs); overflow-wrap: anywhere; }
.group-value-collapsed { max-height: 3em; overflow: hidden; overflow-wrap: anywhere; }
.mapping-tabs :deep(.el-tabs__active-bar) { transition: none; }
.usage-box { margin: var(--ot-space-sm) 0; color: var(--ot-text-secondary); }
.field-hint { color: var(--ot-text-secondary); font-size: var(--ot-font-size-xs); }
</style>
