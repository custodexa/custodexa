<template>
  <div
    class="group-members-tab"
    data-test="group-members-tab"
  >
    <section class="block">
      <p class="hint">
        {{ $t('userGroups.detail.members.help') }}
      </p>
      <el-table
        :data="memberRows"
        size="small"
        data-test="member-table"
      >
        <el-table-column
          prop="username"
          :label="$t('common.name')"
        />
        <el-table-column :label="$t('userGroups.detail.members.colJoinedVia')">
          <template #default="{ row }">
            <el-tag
              size="small"
              :type="row.mapped ? 'warning' : 'info'"
              :data-test="`member-source-${row.id}`"
            >
              {{ row.label }}
            </el-tag>
          </template>
        </el-table-column>
        <template #empty>
          {{ $t('userGroups.noMembers') }}
        </template>
      </el-table>
    </section>

    <section class="block">
      <h3>{{ $t('userGroups.detail.members.title') }}</h3>
      <el-alert
        v-if="protectedRole"
        type="warning"
        :closable="false"
        show-icon
        :title="$t('userGroups.detail.members.maintainBlocked', { role: roleLabel(protectedRole) })"
        data-test="maintain-blocked"
      />
      <template v-else>
        <el-transfer
          v-model="manualIds"
          :data="transferUsers"
          :titles="[$t('userGroups.detail.members.allUsers'), $t('userGroups.detail.members.manualMembers')]"
          filterable
          :filter-placeholder="$t('userGroups.searchUsersPlaceholder')"
          data-test="member-transfer"
        />
        <div
          class="mapped-readonly"
          data-test="mapped-readonly"
        >
          <strong>{{ $t('userGroups.detail.members.mappedReadonlyTitle') }}</strong>
          <span class="hint">{{ $t('userGroups.detail.members.mappedReadonlyNote') }}</span>
          <div
            v-for="user in mappedUsers"
            :key="user.id"
          >
            {{ user.username }}
          </div>
          <span
            v-if="!mappedUsers.length"
            class="hint"
          >{{ $t('identityGroupMappings.noMappedMembers') }}</span>
        </div>
        <div class="actions">
          <el-button
            type="primary"
            :disabled="!dirty"
            :loading="saving"
            data-test="members-save"
            @click="save"
          >
            {{ $t('common.save') }}
          </el-button>
        </div>
      </template>
    </section>

    <DangerComboConfirm
      v-model="confirmOpen"
      :preview="confirmPreview"
      :unavailable="confirmUnavailable"
      :known-subjects="knownSubjects"
      :notify-message="notifyMessage"
      :footnote="$t('dangerConfirm.mappedUnaffected')"
      @confirm="confirmSave"
      @back="confirmOpen = false"
    />
  </div>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { t } from '@/i18n'
import { replaceUserGroupMembers } from '@/api/userGroups'
import { useAssignmentPreview } from '@/composables/useAssignmentPreview'
import { needsDangerConfirm } from '@/utils/dangerCombo'
import { roleLabel } from '@/constants/roles'
import { apiErrorSummary } from '@/api/redact'
import DangerComboConfirm from '@/components/DangerComboConfirm.vue'
import { managementRoleNames } from '../groupProtection'

/**
 * 群組詳情的成員分頁：成員與加入方式、穿梭框維護（只改手動成員）、儲存前預覽與確認。
 * 群組帶受保護角色時整塊停用並說明；伺服器仍是最終裁決。
 * 預覽失敗不擋儲存。
 */
const props = defineProps({
  group: { type: Object, required: true },
  users: { type: Array, default: () => [] },
  protectedRole: { type: String, default: '' },
  bindings: { type: Array, default: () => [] },
  definitions: { type: Array, default: () => [] },
})
const emit = defineEmits(['changed'])

const initialManual = () => [...(props.group.manual_user_ids || [])]
const manualIds = ref(initialManual())
const saving = ref(false)
watch(
  () => props.group,
  () => {
    manualIds.value = initialManual()
  }
)

const sourceOf = (id) => (props.group.member_sources || []).find((m) => m.user_id === id)
const sourceLabel = (id) => {
  const row = sourceOf(id)
  if (row?.manual && row?.mapped) return t('identityGroupMappings.memberBoth')
  if (row?.mapped) return t('identityGroupMappings.memberMapped')
  return t('identityGroupMappings.memberManual')
}
const memberRows = computed(() =>
  (props.group.users || []).map((u) => ({
    id: u.id,
    username: u.username,
    mapped: !!sourceOf(u.id)?.mapped,
    label: sourceLabel(u.id),
  }))
)
const mappedUsers = computed(() =>
  (props.group.users || []).filter((u) => (props.group.mapped_user_ids || []).includes(u.id))
)
const transferUsers = computed(() => props.users.map((u) => ({ key: u.id, label: u.username })))
const knownSubjects = computed(() => props.users.map((u) => ({ user_id: u.id, name: u.username })))

const dirty = computed(() => {
  const a = [...manualIds.value].sort((x, y) => x - y)
  const b = initialManual().sort((x, y) => x - y)
  return a.length !== b.length || a.some((v, i) => v !== b[i])
})
const newlyAdded = computed(() => manualIds.value.filter((id) => !initialManual().includes(id)))

// —— 儲存前預覽與確認 ——
const preview = useAssignmentPreview()
const previewBody = () => ({
  kind: 'group_members',
  group_id: props.group.id,
  manual_member_ids: [...manualIds.value],
})
const confirmOpen = ref(false)
const confirmPreview = ref(null)
const confirmUnavailable = ref(false)
const notifyMessage = computed(() => {
  const p = confirmPreview.value
  if (!p) return ''
  const op = p.operation || {}
  if (['increase', 'decrease'].includes(op.self_direction) || (p.subjects || []).some((s) => s.self)) {
    return t('dangerConfirm.notify.selfChange')
  }
  if ((op.marks || []).includes('management_grant')) {
    const roles = managementRoleNames(
      props.bindings.map((b) => b.role_id),
      props.definitions
    )
      .map(roleLabel)
      .join('、')
    return t('dangerConfirm.notify.groupMembers', { role: roles, n: newlyAdded.value.length })
  }
  return ''
})

const persist = async () => {
  saving.value = true
  try {
    await replaceUserGroupMembers(props.group.id, [...manualIds.value])
    ElMessage.success(t('userGroups.membersUpdated'))
    preview.cancel()
    emit('changed')
  } catch (error) {
    console.error(...apiErrorSummary('user_group_members_failed', error))
  } finally {
    saving.value = false
  }
}

const save = async () => {
  if (!dirty.value || saving.value || props.protectedRole) return
  saving.value = true
  let outcome
  try {
    outcome = await preview.run(previewBody())
  } finally {
    saving.value = false
  }
  if (!outcome.ok) {
    confirmPreview.value = null
    confirmUnavailable.value = true
    confirmOpen.value = true
    return
  }
  if (needsDangerConfirm(outcome.data)) {
    confirmPreview.value = outcome.data
    confirmUnavailable.value = false
    confirmOpen.value = true
    return
  }
  await persist()
}
const confirmSave = async () => {
  confirmOpen.value = false
  await persist()
}

defineExpose({ manualIds })
</script>

<style scoped>
.group-members-tab {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-lg);
}
.block {
  padding: var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}
.block h3 {
  margin: 0 0 var(--ot-space-sm);
  font-size: var(--ot-font-size-md);
  color: var(--ot-text-primary);
}
.hint {
  margin: var(--ot-space-xs) 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}
.mapped-readonly {
  margin-top: var(--ot-space-md);
  color: var(--ot-text-secondary);
  line-height: 1.8;
}
.actions {
  display: flex;
  justify-content: flex-end;
  margin-top: var(--ot-space-md);
}
</style>
