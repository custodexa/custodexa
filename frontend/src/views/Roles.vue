<template>
  <div class="roles">
    <PageHeader
      :title="$t('menu.roles')"
      :description="$t('roles.headerDesc')"
    />

    <!-- 角色列表 -->
    <div class="list-card">
      <el-table
        v-loading="loading"
        :data="roleList"
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
          :label="$t('roles.nameColumn')"
          width="150"
        >
          <template #default="{ row }">
            <el-tag :type="roleTagType(row.name)">
              {{ roleLabel(row.name) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column
          prop="description"
          :label="$t('roles.descriptionColumn')"
          min-width="300"
        >
          <template #default="{ row }">
            {{ roleDescription(row.name) || row.description }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.createdAt')"
          width="180"
        >
          <template #default="{ row }">
            {{ formatDateTime(row.created_at) }}
          </template>
        </el-table-column>
        <template #empty>
          <EmptyState
            :title="$t('roles.emptyTitle')"
            :hint="$t('roles.emptyHint')"
          />
        </template>
      </el-table>
    </div>

    <!-- 權限說明卡片 -->
    <div
      class="info-card"
      style="margin-top: var(--ot-space-md)"
    >
      <div class="card-header">
        <span class="card-title">{{ $t('roles.permissionCardTitle') }}</span>
      </div>
      <!-- 由 ROLE_META 逐角色渲染（role-enum-metadata-sync）：
           以後端角色列表為序，新增角色補一筆 META 即連動，勿再手寫段落 -->
      <el-descriptions
        :column="1"
        border
      >
        <el-descriptions-item
          v-for="role in roleList"
          :key="role.name"
        >
          <template #label>
            <el-tag :type="roleTagType(role.name)">
              {{ roleLabel(role.name) }} ({{ role.name }})
            </el-tag>
          </template>
          {{ roleDescription(role.name) || role.description }}
        </el-descriptions-item>
      </el-descriptions>
    </div>

    <!-- 提示信息 -->
    <el-alert
      :title="$t('roles.tipTitle')"
      type="info"
      :closable="false"
      style="margin-top: var(--ot-space-md)"
    >
      {{ $t('roles.tipBody') }}
    </el-alert>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { getRoleList } from '@/api/user'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import { formatDateTime } from '@/utils/format'
import { roleLabel, roleTagType, roleDescription } from '@/constants/roles'

// 資料狀態
const loading = ref(false)
const roleList = ref([])

// 取得角色列表
const fetchRoleList = async () => {
  loading.value = true
  try {
    const response = await getRoleList()
    roleList.value = response.data || []
  } catch (error) {
    console.error('取得角色列表失敗:', error)
  } finally {
    loading.value = false
  }
}

// 掛載時取得資料
onMounted(() => {
  fetchRoleList()
})
</script>

<style scoped>
.roles {
  /* MainLayout main-content 已有 padding，此處不重複加 */
}

.list-card {
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  min-height: 300px;
}

.info-card {
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.card-header {
  margin-bottom: var(--ot-space-md);
}

.card-title {
  font-size: var(--ot-font-size-md);
  font-weight: 600;
  color: var(--ot-text-primary);
}
</style>
