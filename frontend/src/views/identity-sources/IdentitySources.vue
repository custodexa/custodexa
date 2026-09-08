<template>
  <div class="identity-sources">
    <PageHeader
      :title="$t('identitySources.title')"
      :description="$t('identitySources.headerDesc')"
    >
      <template #actions>
        <el-button
          type="primary"
          @click="addVisible = true"
        >
          <el-icon><Plus /></el-icon>
          {{ $t('identitySources.add') }}
        </el-button>
        <el-button
          :loading="loading"
          @click="fetchAll"
        >
          <el-icon><RefreshCw /></el-icon>
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>

    <!-- 解封能力前提（沿兩個前身頁的同一條不變式）：封印期只認本地 admin 憑證，
         全員改走外部身分來源會使遇 KEK 重啟時無人能解封 -->
    <el-alert
      v-if="localAdminState === 'none'"
      class="page-alert"
      type="error"
      :title="$t('oidcProviders.localAdminNoneTitle')"
      :description="$t('oidcProviders.localAdminNoneDesc')"
      :closable="false"
      show-icon
    />

    <!-- 讀取失敗與「尚未設定」是兩件事：失敗時空表格不得宣稱任何事實 -->
    <el-alert
      v-if="loadFailed"
      class="page-alert"
      type="error"
      :title="$t('identitySources.loadFailedTitle')"
      :description="$t('identitySources.loadFailedDesc')"
      :closable="false"
      show-icon
    />

    <!-- 合併端點尚未提供時的降級聲明：清單由既有的兩支端點拼出，
         條數欄因此沒有值。說出「哪一欄不可信」比整頁不顯示有用 -->
    <el-alert
      v-if="mergedUnavailable && !loadFailed"
      class="page-alert"
      type="info"
      :title="$t('identitySources.mergedUnavailableTitle')"
      :description="$t('identitySources.mergedUnavailableDesc')"
      :closable="false"
      show-icon
    />

    <div class="list-card">
      <el-table
        v-loading="loading"
        :data="rows"
        style="width: 100%"
        stripe
      >
        <el-table-column
          :label="$t('identitySources.column.type')"
          width="150"
        >
          <template #default="{ row }">
            <el-tag
              size="small"
              effect="plain"
              :type="row.type === 'ldap' ? 'info' : 'success'"
            >
              {{ typeLabel(row.type) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.name')"
          min-width="180"
        >
          <template #default="{ row }">
            <router-link
              class="row-link"
              :to="detailPath(row)"
            >
              {{ row.name || $t('identitySources.unnamed') }}
            </router-link>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('identitySources.column.address')"
          min-width="260"
        >
          <template #default="{ row }">
            <el-tooltip
              :content="row.address"
              placement="top"
            >
              <span class="cell-mono">{{ row.address }}</span>
            </el-tooltip>
          </template>
        </el-table-column>
        <!-- 狀態與最近成功登入合併為一欄：兩者是同一個問題的兩半
             （「這個來源現在有沒有在用」），拆兩欄只是把橫幅讓給空白 -->
        <el-table-column
          :label="$t('common.status')"
          width="220"
        >
          <template #default="{ row }">
            <el-tag
              size="small"
              :type="row.enabled ? 'success' : 'info'"
              :effect="row.enabled ? 'light' : 'plain'"
            >
              {{ row.enabled ? $t('common.enabled') : $t('common.disabled') }}
            </el-tag>
            <div class="cell-sub">
              {{ row.last_login_at
                ? $t('identitySources.lastLoginAt', { time: formatTime(row.last_login_at) })
                : $t('identitySources.neverLoggedIn') }}
            </div>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('identitySources.column.mappings')"
          width="140"
        >
          <template #default="{ row }">
            <span v-if="typeof row.mapping_rule_count === 'number'">
              {{ $t('identitySources.ruleCount', { count: row.mapping_rule_count }) }}
            </span>
            <span
              v-else
              class="cell-unknown"
            >{{ $t('identitySources.ruleCountUnknown') }}</span>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.actions')"
          width="180"
        >
          <template #default="{ row }">
            <el-button
              type="primary"
              size="small"
              link
              @click="$router.push(detailPath(row))"
            >
              {{ $t('identitySources.configure') }}
            </el-button>
            <el-button
              type="danger"
              size="small"
              link
              @click="handleDelete(row)"
            >
              {{ $t('common.delete') }}
            </el-button>
          </template>
        </el-table-column>
        <template #empty>
          <EmptyState
            v-if="!loading"
            :icon="IdCard"
            :title="loadFailed
              ? $t('identitySources.emptyLoadFailedTitle')
              : $t('identitySources.emptyTitle')"
            :hint="loadFailed
              ? $t('identitySources.emptyLoadFailedHint')
              : $t('identitySources.emptyHint')"
          >
            <template
              v-if="!loadFailed"
              #action
            >
              <el-button
                type="primary"
                @click="addVisible = true"
              >
                {{ $t('identitySources.add') }}
              </el-button>
            </template>
          </EmptyState>
        </template>
      </el-table>
    </div>

    <div class="list-note">
      {{ $t('identitySources.listNote') }}
    </div>

    <AddSourceDialog
      v-model="addVisible"
      :directory-exists="directoryExists"
      @picked="goCreate"
    />
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { IdCard, Plus, RefreshCw } from 'lucide-vue-next'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import AddSourceDialog from './components/AddSourceDialog.vue'
import { t } from '@/i18n'
import { formatDateTime } from '@/utils/format'
import { confirmDestructive } from '@/utils/confirm'
import { apiErrorSummary } from '@/api/redact'
import { getIdentitySources, isNotImplemented } from '@/api/identitySources'
import { getOIDCProviders, deleteOIDCProvider } from '@/api/oidc'
import { getLDAPDirectory, deleteLDAPDirectory } from '@/api/ldapDirectory'
import { getLocalAdminCount } from '@/api/user'

const router = useRouter()

const logFailure = (event, error) => console.error(...apiErrorSummary(event, error))

const loading = ref(false)
const loadFailed = ref(false)
// 合併端點不可用：清單改由既有兩支端點拼出，映射條數無值
const mergedUnavailable = ref(false)
const rows = ref([])
const addVisible = ref(false)
const localAdminState = ref('ok')

const directoryExists = computed(() => rows.value.some((r) => r.type === 'ldap'))

const typeLabel = (type) =>
  type === 'ldap' ? t('identitySources.typeLabel.ldap') : t('identitySources.typeLabel.oidc')

const formatTime = (value) => formatDateTime(value)

const detailPath = (row) => `/identity-sources/${row.type}/${row.id}`

/**
 * 合併端點不可用時的替代讀法：兩支既有端點各讀一次再拼。
 *
 * 兩支各自失敗互不影響——目錄未設定是正常狀態，提供者清單失敗才是讀取失敗。
 * @returns {Promise<Array>}
 */
const fetchLegacyRows = async () => {
  const out = []
  const providers = await getOIDCProviders()
  for (const p of providers?.data || []) {
    out.push({
      type: 'oidc',
      id: p.id,
      name: p.name,
      address: p.issuer,
      enabled: p.enabled === true,
      last_login_at: p.last_login_at || null,
      mapping_rule_count: null,
    })
  }
  try {
    const dir = await getLDAPDirectory()
    if (dir?.configured === true) {
      out.unshift({
        type: 'ldap',
        id: dir.id || 1,
        name: dir.name,
        address: dir.url,
        enabled: dir.enabled === true,
        last_login_at: dir.last_login_at || null,
        mapping_rule_count: null,
      })
    }
  } catch (error) {
    // 目錄讀取失敗不得吞掉已讀到的提供者清單；缺的那一列由降級聲明說明
    logFailure('identity_source_directory_load_failed', error)
  }
  return out
}

const fetchAll = async () => {
  loading.value = true
  try {
    const res = await getIdentitySources()
    rows.value = res?.data || []
    mergedUnavailable.value = false
    loadFailed.value = false
  } catch (error) {
    if (!isNotImplemented(error)) {
      loadFailed.value = true
      logFailure('identity_sources_load_failed', error)
      loading.value = false
      return
    }
    mergedUnavailable.value = true
    try {
      rows.value = await fetchLegacyRows()
      loadFailed.value = false
    } catch (legacyError) {
      loadFailed.value = true
      logFailure('identity_sources_legacy_load_failed', legacyError)
    }
  } finally {
    loading.value = false
  }
}

// 回應缺 count 欄位與請求失敗同義：狀態未知一律 fail-safe
const fetchLocalAdminState = async () => {
  try {
    const res = await getLocalAdminCount()
    localAdminState.value = typeof res?.count === 'number' && res.count > 0 ? 'ok' : 'none'
  } catch (error) {
    localAdminState.value = 'ok'
    logFailure('local_admin_count_failed', error)
  }
}

const goCreate = (type) => {
  addVisible.value = false
  router.push(`/identity-sources/new/${type}`)
}

const handleDelete = async (row) => {
  try {
    await confirmDestructive(
      t('identitySources.deleteConfirm', { name: row.name || row.address }),
      t('common.deleteConfirmTitle'),
      {
        confirmButtonText: t('common.deleteConfirmButton'),
        cancelButtonText: t('common.cancel'),
      }
    )
  } catch {
    return
  }
  try {
    if (row.type === 'ldap') {
      await deleteLDAPDirectory()
    } else {
      await deleteOIDCProvider(row.id)
    }
    ElMessage.success(t('identitySources.deleted'))
    fetchAll()
  } catch (error) {
    // 仍有映射規則或仍有外部身分關聯時後端回 409，由全域攔截器譯文提示
    logFailure('identity_source_delete_failed', error)
  }
}

onMounted(() => {
  fetchAll()
  fetchLocalAdminState()
})
</script>

<style scoped>
.page-alert {
  margin-bottom: var(--ot-space-md);
}

.list-card {
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  padding: var(--ot-space-md);
}

.row-link {
  color: var(--ot-primary, var(--el-color-primary));
  text-decoration: none;
}

.cell-mono {
  font-family: var(--ot-font-mono, monospace);
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* 最近成功登入：狀態標籤的第二行，不另立一欄 */
.cell-sub {
  margin-top: 2px;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

.cell-unknown {
  color: var(--ot-text-disabled);
}

.list-note {
  margin-top: var(--ot-space-md);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.7;
}
</style>
