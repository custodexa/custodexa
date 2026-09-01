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
        />
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
                {{ u.username }}
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
              @click="handleDelete(row)"
            >
              <el-icon><Trash2 /></el-icon>
              {{ $t('common.delete') }}
            </el-button>
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
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, RefreshCw, SquarePen, Trash2, User } from 'lucide-vue-next'
import {
  getUserGroups,
  createUserGroup,
  updateUserGroup,
  deleteUserGroup,
  replaceUserGroupMembers,
  getUserGroupAuthorizationCount,
} from '@/api/userGroups'
import { getUsers } from '@/api/auth'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import { t } from '@/i18n'

const loading = ref(false)
const groupList = ref([])
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

const fetchGroups = async () => {
  loading.value = true
  try {
    const res = await getUserGroups()
    groupList.value = res.data || []
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
  memberIds.value = (row.users || []).map(u => u.id)
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
</style>
