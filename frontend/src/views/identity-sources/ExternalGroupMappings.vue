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
    <MappingTimingNotice />

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

    <p
      v-if="tab === 'roles'"
      class="field-hint"
      data-test="mapping-roles-tab-hint"
    >
      {{ $t('identityGroupMappings.rolesTabHint') }}
    </p>
    <el-alert
      v-if="tab === 'userGroups' && groupListFailed"
      type="warning"
      :closable="false"
      data-test="mapping-group-list-failed"
      :title="$t('identityGroupMappings.groupListFailed')"
    >
      <el-button
        size="small"
        link
        @click="loadGroupData"
      >
        {{ $t('common.retry') }}
      </el-button>
    </el-alert>
    <el-alert
      v-if="tab === 'userGroups' && groupRolesFailed"
      type="warning"
      :closable="false"
      data-test="mapping-group-roles-unavailable"
      :title="$t('identityGroupMappings.groupRolesUnavailable')"
    >
      <el-button
        size="small"
        link
        @click="loadGroupData"
      >
        {{ $t('common.retry') }}
      </el-button>
    </el-alert>

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
          {{ tab === 'roles' ? roleLabel(row.role) : row.user_group_name }}
          <div
            v-if="tab === 'userGroups' && rolesLineOf(row)"
            class="group-value"
            data-test="mapping-target-roles"
          >
            {{ rolesLineOf(row) }}
          </div>
          <div
            v-if="isLocked(row)"
            class="group-value"
            data-test="mapping-protected-row"
          >
            {{ $t('identityGroupMappings.protectedRow') }}
          </div>
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
            :disabled="isLocked(row)"
            data-test="mapping-edit"
            @click="openEdit(row)"
          >
            {{ $t('common.edit') }}
          </el-button>
          <el-button
            size="small"
            link
            :disabled="isLocked(row)"
            data-test="mapping-toggle"
            @click="toggle(row)"
          >
            {{ row.enabled ? $t('identityGroupMappings.disable') : $t('identityGroupMappings.enable') }}
          </el-button>
          <el-button
            size="small"
            type="danger"
            link
            :disabled="isLocked(row)"
            data-test="mapping-remove"
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

    <p
      class="field-hint"
      data-test="mapping-footer-rule"
    >
      {{ $t('identityGroupMappings.footerRule') }}
    </p>

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
            :placeholder="matchPlaceholder"
            @select="selectExternalGroup"
          />
          <!-- 填群組值時才用得到的比對說明：放在欄位下，不放頁首 -->
          <div
            class="field-hint"
            data-test="mapping-match-hint"
          >
            {{ matchHint }}
          </div>
          <div
            v-if="isEntraSource"
            class="field-hint"
            data-test="mapping-entra-hint"
          >
            {{ $t('identitySources.mapping.entraMatchHint') }}
          </div>
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
              v-for="role in directRoles"
              :key="role.name"
              :label="roleLabel(role.name)"
              :value="role.name"
              :disabled="role.assignment_state === 'protected' || role.assignment_state === 'not_open'"
            >
              <span>{{ roleLabel(role.name) }}</span>
              <span
                v-if="role.assignment_state === 'protected'"
                class="option-reason"
              >{{ $t('identityGroupMappings.protectedOption') }}</span>
              <span
                v-else-if="role.assignment_state === 'not_open'"
                class="option-reason"
              >{{ $t('roles.assignState.notOpen') }}</span>
            </el-option>
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
              :disabled="Boolean(protectedRoleOfGroup(group.id))"
            >
              <span>{{ group.name }}</span>
              <span
                v-if="protectedRoleOfGroup(group.id)"
                class="option-reason"
              >{{ $t('identityGroupMappings.protectedOption') }}</span>
            </el-option>
          </el-select>
          <div
            v-if="tab === 'roles'"
            class="field-hint"
            data-test="mapping-admin-note"
          >
            {{ $t('identitySources.mapping.adminNote') }}
          </div>
          <div
            v-if="tab === 'roles'"
            class="field-hint"
            data-test="mapping-direct-hint"
          >
            {{ $t('identityGroupMappings.directMapHint') }}
          </div>
          <div
            v-if="managementHint"
            class="field-hint"
            data-test="mapping-management-hint"
          >
            {{ managementHint }}
          </div>
          <div
            v-if="directoryHint"
            class="field-hint"
            data-test="mapping-directory-hint"
          >
            {{ directoryHint }}
          </div>
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

    <DangerComboConfirm
      v-model="confirmOpen"
      :preview="confirmPreview"
      :unavailable="confirmUnavailable"
      :notify-message="confirmNotify"
      :footnote="confirmFootnote"
      @back="cancelConfirm"
      @confirm="proceedConfirm"
    />

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
import MappingTimingNotice from '@/components/MappingTimingNotice.vue'
import { t } from '@/i18n'
import { listRoleDefinitions } from '@/api/roleDefinitions'
import { getUserGroups, getUserGroupRoleBindings } from '@/api/userGroups'
import { useRuleChangeGate } from './useRuleChangeGate'
import { roleLabel } from '@/constants/roles'
import DangerComboConfirm from '@/components/DangerComboConfirm.vue'
import { protectedRoleOf, managementRoleNames } from '@/views/usergroups/groupProtection'
import { errorCode, getIdentitySources, getRoleMappings, createRoleMapping, updateRoleMapping, deleteRoleMapping, getUserGroupMappings, getUserGroupMappingUsage, createUserGroupMapping, updateUserGroupMapping, deleteUserGroupMapping, getExternalGroups, updateExternalGroupNote } from '@/api/identitySources'
import { confirmWarnings } from '@/utils/mappingRiskGate'
import { isEntraIssuer } from '@/utils/entraIssuer'

const route = useRoute()
const sourceType = computed(() => String(route.params.type || ''))
const sourceId = computed(() => String(route.params.id || ''))
const sourceTypeLabel = computed(() => t(`identitySources.typeLabel.${sourceType.value}`))
// 目錄依辨識名稱解析後比對，提供者逐字比對；Entra 另交代群組物件識別碼的取得位置
const isDirectorySource = computed(() => sourceType.value === 'ldap')
const isEntraSource = computed(() => sourceType.value === 'oidc' && isEntraIssuer(source.value?.address))
const matchPlaceholder = computed(() => isDirectorySource.value ? t('identitySources.mapping.matchDnPlaceholder') : t('identitySources.mapping.matchClaimValuePlaceholder'))
const matchHint = computed(() => isDirectorySource.value ? t('identitySources.mapping.matchDnHint') : t('identitySources.mapping.matchClaimValueHint'))
const source = ref(null)
const definitions = ref([])
const userGroups = ref([])
const groupBindings = ref(new Map())
const groupListFailed = ref(false)
const groupRolesFailed = ref(false)
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
  const options = rows.value.map(row => tab.value === 'roles' ? { value: row.role, label: roleLabel(row.role) } : { value: row.user_group_id, label: row.user_group_name })
  return [...new Map(options.map(item => [item.value, item])).values()]
})
const visibleRows = computed(() => targetFilter.value ? rows.value.filter(row => (tab.value === 'roles' ? row.role : row.user_group_id) === targetFilter.value) : rows.value)
// 角色規則只列可直接映射者；其餘（自訂、需要範圍的角色）要經使用者群組
const directRoles = computed(() => definitions.value.filter(d => d.direct_mappable === true))
const defByName = (name) => definitions.value.find(d => d.name === name)
const protectedRoleOfGroup = (id) => protectedRoleOf(groupBindings.value.get(id), definitions.value)
const managementRolesOfGroup = (id) => managementRoleNames((groupBindings.value.get(id) || []).map(b => b.role_id), definitions.value).map(roleLabel)
const rolesLineOf = (row) => {
  const list = groupBindings.value.get(row.user_group_id)
  if (!list) return ''
  if (!list.length) return t('identityGroupMappings.targetNoRoles')
  return t('identityGroupMappings.targetRoles', { roles: list.map(b => roleLabel(b.role_name)).join('、') })
}
// 依舊目標鎖定：目標帶「只有超級管理者能增減」的角色（伺服器依操作者算出的分類），列的編輯、啟用／停用、刪除停用
const isLocked = (row) => tab.value === 'roles'
  ? defByName(row.role)?.assignment_state === 'protected'
  : Boolean(protectedRoleOfGroup(row.user_group_id))
const targetProtectedRole = (type, role, groupId) => type === 'roles'
  ? (defByName(role)?.assignment_state === 'protected' ? role : '')
  : protectedRoleOfGroup(groupId)
const targetManagementRoles = (type, role, groupId) => {
  if (type === 'roles') {
    const def = defByName(role)
    return def?.management_class ? [roleLabel(def.name)] : []
  }
  return managementRolesOfGroup(groupId)
}
const managementHint = computed(() => {
  const names = targetManagementRoles(tab.value, draft.value.role, draft.value.user_group_id)
  if (!names.length) return ''
  return t(tab.value === 'roles' ? 'identityGroupMappings.managementRoleTarget' : 'identityGroupMappings.managementTarget', { role: names.join('、') })
})
const directoryHint = computed(() => {
  const protectedRole = targetProtectedRole(tab.value, draft.value.role, draft.value.user_group_id)
  if (protectedRole) {
    return `${t('identityGroupMappings.protectedTarget', { role: roleLabel(protectedRole) })} ${t('identityGroupMappings.externalDirectoryDecides', { role: roleLabel(protectedRole) })}`
  }
  const names = targetManagementRoles(tab.value, draft.value.role, draft.value.user_group_id)
  return names.length ? t('identityGroupMappings.externalDirectoryDecides', { role: names.join('、') }) : ''
})
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
    const [sources, roleResult, groupResult, roleDefs, dictionary] = await Promise.all([
      getIdentitySources(), getRoleMappings(sourceType.value, sourceId.value), getUserGroupMappings(sourceType.value, sourceId.value), listRoleDefinitions(), getExternalGroups(sourceType.value, sourceId.value),
    ])
    source.value = (sources.data || []).find(item => item.type === sourceType.value && String(item.id) === sourceId.value) || null
    roleRows.value = roleResult.data || []
    groupRows.value = groupResult.data || []
    externalGroups.value = dictionary.data || []
    definitions.value = roleDefs.data || []
  } catch (error) {
    ElMessage.error(t('identityGroupMappings.loadFailed'))
    console.error('identity_group_mappings_load_failed', error)
  } finally { loading.value = false }
  await loadGroupData()
}

// 使用者群組清單與各群組帶有的角色：讀不到時就地說明，不擋頁面；讀不到角色時選項不預先停用，由伺服器寫入時裁決
const loadGroupData = async () => {
  groupListFailed.value = false
  groupRolesFailed.value = false
  try {
    const result = await getUserGroups()
    userGroups.value = result.data || []
  } catch (error) {
    userGroups.value = []
    groupBindings.value = new Map()
    groupListFailed.value = true
    console.error('identity_group_mappings_group_list_failed', error)
    return
  }
  const settled = await Promise.allSettled(userGroups.value.map(group => getUserGroupRoleBindings(group.id, { quiet: true })))
  const next = new Map()
  settled.forEach((outcome, index) => {
    if (outcome.status === 'fulfilled') next.set(userGroups.value[index].id, outcome.value?.data || [])
    else groupRolesFailed.value = true
  })
  groupBindings.value = next
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
const openEdit = async (row) => {
  if (isLocked(row)) return
  editing.value = row
  draft.value = { match_value: row.match_value, note: row.note || '', role: row.role || '', user_group_id: row.user_group_id || null, enabled: row.enabled }
  dialogOpen.value = true
  if (tab.value === 'userGroups') await loadUsage()
}
const openNote = (row) => { noteRow.value = row; noteDraft.value = row.note || ''; noteOpen.value = true }

const persist = async (payload) => {
  const type = sourceType.value; const id = sourceId.value
  if (tab.value === 'roles') return editing.value ? updateRoleMapping(type, id, editing.value.id, payload) : createRoleMapping(type, id, payload)
  return editing.value ? updateUserGroupMapping(type, id, editing.value.id, payload) : createUserGroupMapping(type, id, payload)
}
// —— 儲存前預覽（建議性）：命中時經確認框；預覽失敗或無權一律標示暫時無法取得，不擋儲存 ——
const { confirmOpen, confirmPreview, confirmUnavailable, confirmNotify, confirmFootnote, gate, proceedConfirm, cancelConfirm } = useRuleChangeGate(busy)
const previewBase = () => ({
  kind: 'mapping_rule_change',
  rule_type: tab.value === 'roles' ? 'role' : 'user_group',
  source_type: sourceType.value,
  source_id: Number(sourceId.value),
})
const targetRef = (role, groupId) => tab.value === 'roles' ? { role_id: defByName(role)?.id } : { group_id: groupId }
const rowTargetName = (row) => tab.value === 'roles' ? row.role : row.user_group_name

const save = async () => {
  if (!canSave.value) return
  const body = {
    ...previewBase(),
    ...(editing.value ? { rule_id: editing.value.id } : {}),
    match_value: draft.value.match_value.trim(),
    ...targetRef(draft.value.role, draft.value.user_group_id),
    enabled: draft.value.enabled,
  }
  const newTarget = tab.value === 'roles' ? draft.value.role : (userGroups.value.find(group => group.id === draft.value.user_group_id)?.name || '')
  const ctx = {
    newTarget,
    managementRoles: targetManagementRoles(tab.value, draft.value.role, draft.value.user_group_id),
    oldTarget: editing.value && targetChanged.value ? rowTargetName(editing.value) : '',
  }
  if (!(await gate(body, ctx))) return
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
  if (isLocked(row)) return
  if (row.enabled && !(await confirmRevocation(row, t('identityGroupMappings.disable')))) return
  const gateBody = { ...previewBase(), rule_id: row.id, enabled: !row.enabled }
  const gateCtx = {
    newTarget: rowTargetName(row),
    managementRoles: targetManagementRoles(tab.value, row.role, row.user_group_id),
    oldTarget: row.enabled ? rowTargetName(row) : '',
  }
  if (!(await gate(gateBody, gateCtx))) return
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
  if (isLocked(row)) return
  if (!(await confirmRevocation(row, t('common.delete')))) return
  const gateBody = { ...previewBase(), rule_id: row.id, delete: true }
  const gateCtx = { newTarget: rowTargetName(row), managementRoles: [], oldTarget: rowTargetName(row) }
  if (!(await gate(gateBody, gateCtx))) return
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
onMounted(() => { loadAll() })
</script>

<style scoped>
.external-mappings { display: grid; gap: var(--ot-space-md); }
.source-summary { display: flex; align-items: center; gap: var(--ot-space-sm); color: var(--ot-text-secondary); }
.table-toolbar { display: flex; justify-content: flex-end; gap: var(--ot-space-sm); }
.group-primary { font-weight: 600; overflow-wrap: anywhere; }
.group-value { color: var(--ot-text-secondary); font-family: var(--ot-font-mono, monospace); font-size: var(--ot-font-size-xs); overflow-wrap: anywhere; }
.group-value-collapsed { max-height: 3em; overflow: hidden; overflow-wrap: anywhere; }
.mapping-tabs :deep(.el-tabs__active-bar) { transition: none; }
.usage-box { margin: var(--ot-space-sm) 0; color: var(--ot-text-secondary); }
.option-reason { margin-left: var(--ot-space-sm); color: var(--ot-text-secondary); font-size: var(--ot-font-size-xs); }
.field-hint { color: var(--ot-text-secondary); font-size: var(--ot-font-size-xs); line-height: 1.6; margin-top: var(--ot-space-xs); }
</style>
