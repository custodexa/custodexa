<template>
  <div class="user-groups">
    <PageHeader
      :title="$t('menu.userGroups')"
      :description="$t('userGroups.headerDesc')"
    >
      <template #actions>
        <el-button
          type="primary"
          @click="openCreateDialog"
        >
          <el-icon><Plus /></el-icon>
          {{ $t('userGroups.create') }}
        </el-button>
        <el-button @click="fetchGroups">
          <el-icon><RefreshCw /></el-icon>
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>

    <div class="list-card">
      <el-table
        v-loading="loading"
        :data="groupList"
        style="width: 100%"
        stripe
      >
        <el-table-column
          prop="id"
          label="ID"
          width="80"
        />
        <el-table-column
          prop="name"
          :label="$t('userGroups.nameColumn')"
          min-width="160"
        >
          <template #default="{ row }">
            <a
              class="group-link"
              :href="rolesTabHref(row.id)"
              :data-test="`group-link-${row.id}`"
              @click.prevent="goDetail(row.id)"
            >{{ row.name }}</a>
            <el-tag
              v-if="protectedRoleByGroup[row.id]"
              size="small"
              type="warning"
              class="protected-tag"
              :data-test="`protected-badge-${row.id}`"
            >
              {{ $t('userGroups.detail.roles.protectedBadge') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column
          prop="description"
          :label="$t('common.description')"
          min-width="200"
        >
          <template #default="{ row }">
            {{ row.description || '-' }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('userGroups.roleScopeColumn')"
          min-width="260"
        >
          <template #default="{ row }">
            <div
              class="role-scope-cell"
              :data-test="`group-roles-${row.id}`"
            >
              <template v-if="roleLinesOf(row.id)">
                <template v-if="roleLinesOf(row.id).length">
                  <span
                    v-for="line in roleLinesOf(row.id)"
                    :key="line.key"
                    class="role-scope-item"
                  >
                    <el-tag
                      size="small"
                      :type="roleTagType(line.name)"
                    >{{ line.label }}</el-tag>
                    <span
                      v-if="line.scope"
                      class="role-scope-text"
                    >{{ line.scope }}</span>
                  </span>
                </template>
                <template v-else>
                  <span class="member-empty">{{ $t('identityGroupMappings.targetNoRoles') }}</span>
                  <a
                    class="group-link"
                    :href="rolesTabHref(row.id)"
                    :data-test="`set-roles-${row.id}`"
                    @click.prevent="goDetail(row.id)"
                  >{{ $t('userGroups.setRoles') }}</a>
                </template>
              </template>
              <span
                v-else
                class="member-empty"
              >-</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('userGroups.members')"
          min-width="220"
        >
          <template #default="{ row }">
            <template v-if="(row.users || []).length">
              <el-tag
                v-for="u in (row.users || []).slice(0, 5)"
                :key="u.id"
                size="small"
                class="member-tag"
              >
                {{ u.username }} · {{ memberSourceLabel(row, u.id) }}
              </el-tag>
              <span
                v-if="(row.users || []).length > 5"
                class="member-more"
              >{{ $t('userGroups.memberMore', { n: row.users.length }) }}</span>
            </template>
            <span
              v-else
              class="member-empty"
            >{{ $t('userGroups.noMembers') }}</span>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.actions')"
          width="220"
          fixed="right"
        >
          <template #default="{ row }">
            <el-button
              type="primary"
              size="small"
              link
              :disabled="!!protectedRoleByGroup[row.id]"
              :data-test="`members-${row.id}`"
              @click="openMembersDialog(row)"
            >
              <el-icon><User /></el-icon>
              {{ $t('userGroups.members') }}
            </el-button>
            <el-button
              type="primary"
              size="small"
              link
              @click="openEditDialog(row)"
            >
              <el-icon><SquarePen /></el-icon>
              {{ $t('common.edit') }}
            </el-button>
            <el-button
              type="danger"
              size="small"
              link
              :disabled="!!protectedRoleByGroup[row.id]"
              :data-test="`delete-${row.id}`"
              @click="handleDelete(row)"
            >
              <el-icon><Trash2 /></el-icon>
              {{ $t('common.delete') }}
            </el-button>
            <div
              v-if="protectedRoleByGroup[row.id]"
              class="protected-note"
              :data-test="`delete-blocked-${row.id}`"
            >
              {{ $t('userGroups.detail.members.deleteBlocked', { role: roleLabel(protectedRoleByGroup[row.id]) }) }}
            </div>
          </template>
        </el-table-column>
        <template #empty>
          <EmptyState
            :title="$t('userGroups.emptyTitle')"
            :hint="$t('userGroups.emptyHint')"
          />
        </template>
      </el-table>
    </div>

    <!-- 建立/編輯對話框 -->
    <el-dialog
      v-model="formDialogVisible"
      :title="isEdit ? $t('userGroups.editTitle') : $t('userGroups.create')"
      width="480px"
      :close-on-click-modal="false"
    >
      <el-form
        ref="formRef"
        :model="form"
        :rules="formRules"
        label-position="top"
      >
        <el-form-item
          :label="$t('common.name')"
          prop="name"
        >
          <el-input
            v-model="form.name"
            maxlength="100"
            :placeholder="$t('userGroups.namePlaceholder')"
          />
        </el-form-item>
        <el-form-item
          :label="$t('common.description')"
          prop="description"
        >
          <el-input
            v-model="form.description"
            type="textarea"
            :rows="3"
            maxlength="500"
            show-word-limit
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="formDialogVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="submitting"
          @click="submitForm"
        >
          {{ $t('common.confirm') }}
        </el-button>
      </template>
    </el-dialog>

    <!-- 成員維護對話框（全量替換語義） -->
    <el-dialog
      v-model="membersDialogVisible"
      :title="$t('userGroups.membersDialogTitle', { name: activeGroup?.name || '' })"
      width="680px"
      :close-on-click-modal="false"
    >
      <el-transfer
        v-model="memberIds"
        :data="transferUsers"
        :titles="[$t('userGroups.transferAll'), $t('userGroups.transferMembers')]"
        filterable
        :filter-placeholder="$t('userGroups.searchUsersPlaceholder')"
      />
      <div class="mapped-members">
        <strong>{{ $t('identityGroupMappings.mappedMembers') }}</strong>
        <div
          v-for="user in mappedUsers"
          :key="user.id"
        >
          {{ user.username }} · {{ memberSourceLabel(activeGroup, user.id) }}
        </div>
        <span v-if="!mappedUsers.length">{{ $t('identityGroupMappings.noMappedMembers') }}</span>
      </div>
      <template #footer>
        <el-button @click="membersDialogVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="submitting"
          @click="submitMembers"
        >
          {{ $t('common.save') }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, RefreshCw, SquarePen, Trash2, User } from 'lucide-vue-next'
import {
  getUserGroups,
  createUserGroup,
  updateUserGroup,
  deleteUserGroup,
  replaceUserGroupMembers,
  getUserGroupAuthorizationCount,
  getUserGroupRoleBindings,
} from '@/api/userGroups'
import { listRoleDefinitions, getRoleAssignmentOptions } from '@/api/roleDefinitions'
import { roleLabel, roleTagType } from '@/constants/roles'
import { can } from '@/composables/useCapabilities'
import { describeAssignment, fromGroupBinding } from '@/utils/roleScopePresentation'
import { protectedRoleOf } from './usergroups/groupProtection'
import { getUsers } from '@/api/auth'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import { t } from '@/i18n'

const router = useRouter()
const loading = ref(false)
const groupList = ref([])
// 群組帶有受保護角色（只有超級管理者能增減）：groupId → 角色名稱
const protectedRoleByGroup = ref({})
// 角色與管理範圍欄：群組角色指派（列表本來就逐群組讀來判斷受保護群組）、角色定義、
// 指派用節點清單（只對能指派角色者讀取；讀不到時退回節點數）
const bindingsByGroup = ref({})
const roleDefs = ref([])
const roleDefsReady = ref(false)
const assignNodes = ref(null)
const assignReasons = ref({})
const userList = ref([])

// 建立/編輯
const formDialogVisible = ref(false)
const isEdit = ref(false)
const submitting = ref(false)
const formRef = ref(null)
const form = ref({ id: null, name: '', description: '' })
const formRules = computed(() => ({
  name: [{ required: true, message: t('userGroups.nameRequired'), trigger: 'blur' }],
}))

// 成員維護
const membersDialogVisible = ref(false)
const activeGroup = ref(null)
const memberIds = ref([])
const transferUsers = computed(() =>
  userList.value.map(u => ({ key: u.id, label: u.username }))
)
const mappedUsers = computed(() => (activeGroup.value?.users || []).filter(user =>
  (activeGroup.value?.mapped_user_ids || []).includes(user.id)
))
const memberSourceLabel = (group, userId) => {
  const row = (group?.member_sources || []).find(item => item.user_id === userId)
  if (row?.manual && row?.mapped) return t('identityGroupMappings.memberBoth')
  if (row?.mapped) return t('identityGroupMappings.memberMapped')
  return t('identityGroupMappings.memberManual')
}

const rolesTabHref = (id) => `/user-groups/${id}?tab=roles`
const goDetail = (id) => router?.push(rolesTabHref(id))

// 一個群組的角色行：可限定節點且範圍會生效的角色寫出管理範圍，其他角色只列名稱
const roleLinesOf = (groupId) => {
  const list = bindingsByGroup.value[groupId]
  if (!list) return null
  const ctx = { nodes: assignNodes.value, canReadPaths: can('role:assign') }
  return list.map((b) => {
    const described = describeAssignment(
      fromGroupBinding(b),
      roleDefs.value.find((d) => d.id === b.role_id),
      assignReasons.value[String(b.role_id)],
      ctx
    )
    return {
      key: b.role_id,
      name: b.role_name,
      label: roleLabel(b.role_name),
      scope: roleDefsReady.value && described.showScope ? described.scope.text : '',
    }
  })
}

// 分類取自伺服器對操作者算出的 assignment_state；讀不到時不停用，由伺服器在寫入時裁決
const loadAssignOptions = async () => {
  if (!can('role:assign')) {
    assignNodes.value = null
    assignReasons.value = {}
    return
  }
  try {
    const res = await getRoleAssignmentOptions()
    assignNodes.value = Array.isArray(res?.nodes) ? res.nodes : null
    assignReasons.value = res?.node_range_no_effect_reasons || {}
  } catch (err) {
    assignNodes.value = null
    assignReasons.value = {}
    console.error('取得指派用節點清單失敗:', err)
  }
}

const loadProtection = async (groups) => {
  const optionsDone = loadAssignOptions()
  // 角色定義需要 role:view，讀不到時仍讀角色指派並列出角色名稱（不分類、不寫範圍）
  let defs = []
  try {
    defs = (await listRoleDefinitions())?.data || []
    roleDefsReady.value = true
  } catch (err) {
    roleDefsReady.value = false
    console.error('取得角色定義失敗:', err)
  }
  roleDefs.value = defs
  try {
    const entries = await Promise.all(
      groups.map(async (g) => {
        try {
          const b = await getUserGroupRoleBindings(g.id, { quiet: true })
          return [g.id, protectedRoleOf(b.data || [], defs), b.data || []]
        } catch {
          return [g.id, '', null]
        }
      })
    )
    protectedRoleByGroup.value = Object.fromEntries(entries.filter(([, role]) => role).map(([id, role]) => [id, role]))
    bindingsByGroup.value = Object.fromEntries(entries.filter(([, , list]) => list).map(([id, , list]) => [id, list]))
  } catch (err) {
    protectedRoleByGroup.value = {}
    bindingsByGroup.value = {}
    console.error('取得角色指派失敗:', err)
  }
  await optionsDone
}

const fetchGroups = async () => {
  loading.value = true
  try {
    const res = await getUserGroups()
    groupList.value = res.data || []
    loadProtection(groupList.value)
  } catch (err) {
    console.error('取得使用者群組失敗:', err)
  } finally {
    loading.value = false
  }
}

const fetchUsers = async () => {
  try {
    const res = await getUsers()
    userList.value = res.data || []
  } catch (err) {
    console.error('取得使用者列表失敗:', err)
  }
}

const openCreateDialog = () => {
  isEdit.value = false
  form.value = { id: null, name: '', description: '' }
  formDialogVisible.value = true
}

const openEditDialog = (row) => {
  isEdit.value = true
  form.value = { id: row.id, name: row.name, description: row.description }
  formDialogVisible.value = true
}

const submitForm = async () => {
  if (formRef.value) {
    const valid = await formRef.value.validate().catch(() => false)
    if (!valid) return
  }
  submitting.value = true
  try {
    if (isEdit.value) {
      await updateUserGroup(form.value.id, {
        name: form.value.name,
        description: form.value.description,
      })
      ElMessage.success(t('userGroups.updated'))
    } else {
      await createUserGroup({
        name: form.value.name,
        description: form.value.description,
      })
      ElMessage.success(t('userGroups.created'))
    }
    formDialogVisible.value = false
    fetchGroups()
  } catch (err) {
    console.error('儲存群組失敗:', err)
  } finally {
    submitting.value = false
  }
}

const openMembersDialog = (row) => {
  activeGroup.value = row
  memberIds.value = [...(row.manual_user_ids || (row.users || []).map(u => u.id))]
  membersDialogVisible.value = true
}

const submitMembers = async () => {
  submitting.value = true
  try {
    await replaceUserGroupMembers(activeGroup.value.id, memberIds.value)
    ElMessage.success(t('userGroups.membersUpdated'))
    membersDialogVisible.value = false
    fetchGroups()
  } catch (err) {
    console.error('更新成員失敗:', err)
  } finally {
    submitting.value = false
  }
}

const handleDelete = async (row) => {
  // 先查連動撤銷筆數，讓管理者知道刪除的授權面影響
  let count = 0
  try {
    const res = await getUserGroupAuthorizationCount(row.id)
    count = res.authorization_count || 0
  } catch (err) {
    console.error('查詢群組授權數失敗:', err)
  }

  try {
    await ElMessageBox.confirm(
      count > 0
        ? t('userGroups.deleteConfirmWithAuth', { name: row.name, count })
        : t('userGroups.deleteConfirm', { name: row.name }),
      t('common.deleteConfirmTitle'),
      {
        confirmButtonText: t('common.deleteConfirmButton'),
        cancelButtonText: t('common.cancel'),
        type: 'warning',
      }
    )
  } catch {
    return
  }

  try {
    const res = await deleteUserGroup(row.id)
    ElMessage.success(
      t('userGroups.deleted', { count: res.revoked_authorizations ?? 0 })
    )
    fetchGroups()
  } catch (err) {
    console.error('刪除群組失敗:', err)
  }
}

onMounted(() => {
  fetchGroups()
  fetchUsers()
})
</script>

<style scoped>
.user-groups {
  /* MainLayout main-content 已有 padding */
}

.list-card {
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  padding: var(--ot-space-md);
}

.group-link {
  color: var(--ot-primary);
}

.protected-tag {
  margin-left: var(--ot-space-xs);
}

.role-scope-cell {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--ot-space-xs) var(--ot-space-md);
}

.role-scope-item {
  display: inline-flex;
  align-items: center;
  gap: var(--ot-space-xs);
}

.role-scope-text {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  overflow-wrap: anywhere;
}

.protected-note {
  margin-top: var(--ot-space-xs);
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
  white-space: normal;
}

.member-tag {
  margin-right: 4px;
  margin-bottom: 2px;
}

.member-more {
  color: var(--ot-text-secondary);
  font-size: 12px;
  margin-left: 4px;
}

.member-empty {
  color: var(--ot-text-disabled);
}

.mapped-members {
  margin-top: var(--ot-space-md);
  color: var(--ot-text-secondary);
  line-height: 1.8;
}
</style>
