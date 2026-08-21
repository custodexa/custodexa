<template>
  <div class="effective-view">
    <div class="selector-bar">
      <template v-if="mode === 'subject'">
        <span class="selector-label">{{ $t('authzEffective.selectUserLabel') }}</span>
        <el-select
          v-model="selectedId"
          :placeholder="$t('authzEffective.selectUserPlaceholder')"
          filterable
          clearable
          style="width: 240px"
          @change="fetchData"
        >
          <el-option
            v-for="u in userList"
            :key="u.id"
            :label="u.username"
            :value="u.id"
          />
        </el-select>
      </template>
      <template v-else>
        <span class="selector-label">{{ $t('authzEffective.selectAssetLabel') }}</span>
        <el-select
          v-model="selectedId"
          :placeholder="$t('authzEffective.selectAssetPlaceholder')"
          filterable
          clearable
          style="width: 240px"
          @change="fetchData"
        >
          <el-option
            v-for="a in assetList"
            :key="a.id"
            :label="a.name"
            :value="a.id"
          />
        </el-select>
      </template>
    </div>

    <!-- 主體視角：admin/auditor 角色隱含全可及（role_override 摘要橫幅，不逐列展開） -->
    <el-alert
      v-if="mode === 'subject' && result && result.role_override"
      type="warning"
      :closable="false"
      show-icon
      class="override-banner"
      :title="result.role_override === 'auditor'
        ? $t('authzEffective.roleOverrideBannerAuditor')
        : $t('authzEffective.roleOverrideBanner', { role: result.role_override })"
    />
    <!-- 客體視角：role_override 摘要說明 -->
    <el-alert
      v-if="mode === 'object' && result"
      type="info"
      :closable="false"
      show-icon
      class="override-banner"
      :title="result.role_override_note"
    />

    <el-alert
      v-if="errorMsg"
      type="error"
      :closable="false"
      show-icon
      :title="errorMsg"
    />

    <el-table
      v-if="result && !errorMsg"
      v-loading="loading"
      :data="rows"
      style="width: 100%"
      stripe
    >
      <el-table-column
        type="expand"
      >
        <template #default="{ row }">
          <div class="paths-detail">
            <div
              v-for="(p, idx) in row.paths"
              :key="idx"
              class="path-row"
            >
              <el-tag
                size="small"
                :type="pathKindTagType(p.kind)"
                class="path-tag"
              >
                {{ pathKindText(p.kind) }}
              </el-tag>
              <span
                v-if="p.via_group_name"
                class="path-via"
              >{{ $t('authzEffective.viaGroup', { name: p.via_group_name }) }}</span>
              <span
                v-if="p.via_node_path"
                class="path-via"
              >{{ $t('authzEffective.viaNode', { path: p.via_node_path }) }}</span>
              <el-tag
                size="small"
                :type="p.permission === 'connect' ? 'success' : 'info'"
                class="path-tag"
              >
                {{ $t(p.permission === 'connect' ? 'assets.permission.connect' : 'assets.permission.view') }}
              </el-tag>
              <span
                v-if="p.authorization_id"
                class="path-meta"
              >{{ $t('authzEffective.authRecordRef', { id: p.authorization_id }) }}</span>
              <span
                v-if="p.date_expired"
                class="path-meta"
              >{{ $t('authorizations.untilTime', { time: formatDateTime(p.date_expired) }) }}</span>
            </div>
          </div>
        </template>
      </el-table-column>
      <template v-if="mode === 'subject'">
        <el-table-column
          prop="asset_id"
          :label="$t('authzEffective.colAssetId')"
          width="90"
        />
        <el-table-column
          prop="asset_name"
          :label="$t('common.assetName')"
          min-width="180"
        />
        <el-table-column
          :label="$t('common.protocol')"
          width="110"
        >
          <template #default="{ row }">
            {{ (row.protocol || '').toUpperCase() }}
          </template>
        </el-table-column>
      </template>
      <template v-else>
        <el-table-column
          prop="user_id"
          :label="$t('authzEffective.colUserId')"
          width="100"
        />
        <el-table-column
          prop="username"
          :label="$t('common.user')"
          min-width="180"
        />
      </template>
      <el-table-column
        :label="$t('authzEffective.colEffectivePermission')"
        width="120"
      >
        <template #default="{ row }">
          <el-tag :type="row.permission === 'connect' ? 'success' : 'info'">
            {{ $t(row.permission === 'connect' ? 'assets.permission.connect' : 'assets.permission.view') }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column
        :label="$t('authzEffective.colPathCount')"
        width="90"
      >
        <template #default="{ row }">
          {{ (row.paths || []).length }}
        </template>
      </el-table-column>
      <template #empty>
        <EmptyState
          :title="mode === 'subject' ? $t('authzEffective.emptySubjectTitle') : $t('authzEffective.emptyObjectTitle')"
          :hint="$t('authzEffective.expandHint')"
        />
      </template>
    </el-table>

    <EmptyState
      v-if="!result && !errorMsg && !loading"
      :title="mode === 'subject' ? $t('authzEffective.placeholderSubject') : $t('authzEffective.placeholderObject')"
      :hint="$t('authzEffective.placeholderHint')"
    />
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { getEffectiveAssets, getEffectiveUsers } from '@/api/authorizations'
import { getUsers } from '@/api/auth'
import { getAssetList } from '@/api/assets'
import EmptyState from '@/components/EmptyState.vue'
import { formatDateTime } from '@/utils/format'
import { t } from '@/i18n'

// 有效權限雙視角（authorization-page-redesign D3）：
// subject＝「這個人能連什麼」、object＝「這台機器誰能連」，皆含溯因
const props = defineProps({
  mode: {
    type: String,
    required: true,
    validator: (v) => ['subject', 'object'].includes(v),
  },
})

const selectedId = ref(null)
const result = ref(null)
const loading = ref(false)
const errorMsg = ref('')
const userList = ref([])
const assetList = ref([])

const rows = computed(() => {
  if (!result.value) return []
  return props.mode === 'subject' ? result.value.assets || [] : result.value.users || []
})

const fetchData = async () => {
  result.value = null
  errorMsg.value = ''
  if (!selectedId.value) return
  loading.value = true
  try {
    result.value =
      props.mode === 'subject'
        ? await getEffectiveAssets(selectedId.value)
        : await getEffectiveUsers(selectedId.value)
  } catch (error) {
    console.error('查詢有效權限失敗:', error)
    errorMsg.value = t('authzEffective.queryFailed')
  } finally {
    loading.value = false
  }
}

const pathKindText = (kind) => {
  const map = {
    direct_user: t('authzEffective.pathKind.direct_user'),
    user_group: t('authzEffective.pathKind.user_group'),
    asset_node: t('authzEffective.pathKind.asset_node'),
    user_group_asset_node: t('authzEffective.pathKind.user_group_asset_node'),
    approver_scope: t('authzEffective.pathKind.approver_scope'),
  }
  return map[kind] || kind
}

const pathKindTagType = (kind) => {
  const map = {
    direct_user: 'primary',
    user_group: 'warning',
    asset_node: 'info',
    user_group_asset_node: 'warning',
    approver_scope: 'danger',
  }
  return map[kind] || 'info'
}

onMounted(async () => {
  try {
    if (props.mode === 'subject') {
      const res = await getUsers()
      userList.value = res.data || []
    } else {
      const res = await getAssetList({ page_size: 1000 })
      assetList.value = res.data || []
    }
  } catch (error) {
    console.error('載入選項失敗:', error)
  }
})

defineExpose({ fetchData, selectedId, result })
</script>

<style scoped>
.effective-view {
  min-height: 320px;
}

.selector-bar {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-md);
}

.selector-label {
  color: var(--ot-text-secondary);
  font-size: 14px;
}

.override-banner {
  margin-bottom: var(--ot-space-md);
}

.paths-detail {
  padding: var(--ot-space-sm) var(--ot-space-lg);
}

.path-row {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  padding: 4px 0;
}

.path-tag {
  flex-shrink: 0;
}

.path-via {
  color: var(--ot-text-primary);
  font-size: 13px;
}

.path-meta {
  color: var(--ot-text-secondary);
  font-size: 12px;
}
</style>
