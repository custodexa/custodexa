<template>
  <div class="authorizations">
    <PageHeader
      :title="$t('authorizations.title')"
      :description="$t('authorizations.headerDesc')"
    >
      <template #actions>
        <el-button
          v-if="isAdmin"
          type="primary"
          @click="handleBatchAuthorize"
        >
          <el-icon><Plus /></el-icon>
          {{ $t('authorizations.batchAuthorize') }}
        </el-button>
        <el-button @click="handleRefresh">
          <el-icon><Refresh /></el-icon>
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>

    <el-tabs
      v-model="activeTab"
      class="authz-tabs"
    >
      <el-tab-pane
        :label="$t('authorizations.tabRecords')"
        name="records"
      >
        <!-- 篩選面板 -->
        <div class="filter-bar">
          <el-form
            :inline="true"
            :model="filterForm"
          >
            <el-form-item :label="$t('common.user')">
              <el-select
                v-model="filterForm.user_id"
                :placeholder="$t('authorizations.allUsers')"
                clearable
                filterable
                style="width: 180px"
                @change="handleSubjectFilterChange('user_id')"
              >
                <el-option
                  v-for="user in userList"
                  :key="user.id"
                  :label="user.username"
                  :value="user.id"
                />
              </el-select>
            </el-form-item>
            <el-form-item :label="$t('authorizations.filterUserGroup')">
              <el-select
                v-model="filterForm.user_group_id"
                :placeholder="$t('authorizations.allGroups')"
                clearable
                filterable
                style="width: 180px"
                @change="handleSubjectFilterChange('user_group_id')"
              >
                <el-option
                  v-for="g in userGroupList"
                  :key="g.id"
                  :label="g.name"
                  :value="g.id"
                />
              </el-select>
            </el-form-item>
            <el-form-item :label="$t('common.asset')">
              <el-select
                v-model="filterForm.asset_id"
                :placeholder="$t('authorizations.allAssets')"
                clearable
                filterable
                style="width: 180px"
                @change="handleSubjectFilterChange('asset_id')"
              >
                <el-option
                  v-for="asset in assetList"
                  :key="asset.id"
                  :label="asset.name"
                  :value="asset.id"
                />
              </el-select>
            </el-form-item>
            <!-- 節點涵蓋盤點（authz-tag-node-filters D7）：第四個互斥維度 -->
            <el-form-item>
              <template #label>
                <span>{{ $t('common.node') }}</span>
                <el-tooltip
                  placement="top"
                  :content="$t('authorizations.filterNodeHelp')"
                >
                  <el-icon class="node-filter-help">
                    <QuestionFilled />
                  </el-icon>
                </el-tooltip>
              </template>
              <el-tree-select
                v-model="filterForm.node_id"
                :data="nodeTreeOptions"
                :props="{ label: 'label', children: 'children' }"
                node-key="id"
                check-strictly
                clearable
                filterable
                :placeholder="$t('authorizations.allNodes')"
                style="width: 200px"
                @change="handleSubjectFilterChange('node_id')"
              />
            </el-form-item>
            <el-form-item>
              <el-button
                type="primary"
                @click="handleFilter"
              >
                <el-icon><Search /></el-icon>
                {{ $t('common.search') }}
              </el-button>
              <el-button @click="handleResetFilter">
                <el-icon><Refresh /></el-icon>
                {{ $t('common.reset') }}
              </el-button>
            </el-form-item>
          </el-form>

          <!-- 快速篩選 chip（D7：對應伺服端 validity/source 參數，跨頁正確） -->
          <div class="quick-filters">
            <el-radio-group
              v-model="quickFilter"
              size="small"
              @change="handleQuickFilterChange"
            >
              <el-radio-button value="all">
                {{ $t('common.all') }}
              </el-radio-button>
              <el-radio-button value="active">
                {{ $t('authorizations.filterActive') }}
              </el-radio-button>
              <el-radio-button value="expired">
                {{ $t('authorizations.filterExpired') }}
              </el-radio-button>
              <el-radio-button value="ticket">
                {{ $t('authorizations.temporary') }}
              </el-radio-button>
            </el-radio-group>
          </div>
        </div>

        <!-- 授權列表 -->
        <div class="list-card">
          <!-- 載入失敗誠實呈現（不以空狀態偽裝錯誤） -->
          <el-alert
            v-if="loadError"
            type="error"
            :closable="false"
            show-icon
            :title="$t('authorizations.loadFailed')"
            :description="loadError"
            class="load-error"
          />
          <el-table
            v-loading="loading"
            :data="authorizationList"
            style="width: 100%"
            stripe
            :row-class-name="rowClassName"
          >
            <el-table-column
              prop="id"
              label="ID"
              width="80"
            />
            <el-table-column
              :label="$t('authorizations.colSubject')"
              min-width="150"
            >
              <template #default="{ row }">
                <template v-if="row.user_group_name || row.user_group_id">
                  <el-tag
                    size="small"
                    type="warning"
                    class="target-group-tag"
                  >
                    {{ $t('common.group') }}
                  </el-tag>
                  <span
                    v-if="row.subject_deleted"
                    class="deleted-entity"
                  >{{ $t('authorizations.deletedGroup') }}</span>
                  <template v-else>
                    {{ row.user_group_name }}
                  </template>
                </template>
                <template v-else>
                  <el-tag
                    size="small"
                    type="primary"
                    class="target-group-tag"
                  >
                    {{ $t('common.user') }}
                  </el-tag>
                  <span
                    v-if="row.subject_deleted"
                    class="deleted-entity"
                  >{{ $t('authorizations.deletedUser') }}</span>
                  <template v-else>
                    {{ row.username || '-' }}
                  </template>
                </template>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('authorizations.colTarget')"
              min-width="200"
            >
              <template #default="{ row }">
                <template v-if="row.asset_group_name || row.asset_group_id">
                  <el-tooltip
                    :content="$t('authorizations.nodeTargetTip')"
                    placement="top"
                  >
                    <el-tag
                      size="small"
                      type="info"
                      class="target-group-tag"
                    >
                      {{ $t('common.node') }}
                    </el-tag>
                  </el-tooltip>
                  <span
                    v-if="row.target_deleted"
                    class="deleted-entity"
                  >{{ $t('authorizations.deletedNode') }}</span>
                  <template v-else>
                    {{ row.asset_group_name }}
                  </template>
                </template>
                <template v-else>
                  <span
                    v-if="row.target_deleted"
                    class="deleted-entity"
                  >{{ $t('authorizations.deletedAsset') }}</span>
                  <template v-else>
                    {{ row.asset_name || '-' }}
                  </template>
                </template>
              </template>
            </el-table-column>
            <!-- 帳號範圍（asset-multi-account D5）：預設全部帳號，可個別指定 username -->
            <el-table-column
              :label="$t('authorizations.colAccountScope')"
              min-width="160"
            >
              <template #default="{ row }">
                <el-tag
                  v-if="isAllAccountScope(row.accounts)"
                  size="small"
                  type="info"
                >
                  {{ $t('authorizations.accountScopeAll') }}
                </el-tag>
                <template v-else>
                  <el-tag
                    v-for="name in row.accounts"
                    :key="name"
                    size="small"
                    type="primary"
                    class="account-scope-tag"
                  >
                    {{ name }}
                  </el-tag>
                </template>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.permission')"
              width="100"
            >
              <template #default="{ row }">
                <el-tag :type="getPermissionTagType(row.permission)">
                  {{ getPermissionText(row.permission) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('authorizations.colSourceValidity')"
              min-width="180"
            >
              <template #default="{ row }">
                <template v-if="row.source === 'ticket'">
                  <el-tag
                    size="small"
                    type="warning"
                    class="target-group-tag"
                  >
                    {{ $t('authorizations.temporary') }}
                  </el-tag>
                  <el-tag
                    v-if="row.validity_state === 'expired'"
                    size="small"
                    type="info"
                  >
                    {{ $t('authorizations.expired') }}
                  </el-tag>
                  <el-tag
                    v-else-if="row.validity_state === 'scheduled'"
                    size="small"
                    type="info"
                  >
                    {{ $t('authorizations.scheduled') }}
                  </el-tag>
                  <div
                    v-if="row.date_expired"
                    class="expiry-line"
                    :class="expiryClass(row)"
                  >
                    {{ $t('authorizations.untilTime', { time: formatDateTime(row.date_expired) }) }}
                  </div>
                </template>
                <template v-else>
                  <span class="source-permanent">{{ $t('authorizations.permanent') }}</span>
                </template>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.grantedTime')"
              width="170"
              prop="created_at"
            >
              <template #default="{ row }">
                {{ formatDateTime(row.created_at) }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.actions')"
              width="200"
              fixed="right"
            >
              <template #default="{ row }">
                <!-- 帳號範圍僅 manual 列可改：ticket 列的範圍源自申請單，
                     於此改等於繞過申請與核准（伺服端亦回 409 二道防線） -->
                <el-button
                  v-if="row.source !== 'ticket'"
                  type="primary"
                  size="small"
                  link
                  @click="openAccountScope(row)"
                >
                  <el-icon><Key /></el-icon>
                  {{ $t('authorizations.accountScopeAction') }}
                </el-button>
                <!-- ticket 列按 revocable 分流（D4）：可撤走申請單撤銷流、
                     過期/未生效唯讀留存（審計證據）；manual 照常刪除 -->
                <el-button
                  v-if="row.source === 'ticket' && row.revocable"
                  type="warning"
                  size="small"
                  link
                  @click="handleRevoke(row)"
                >
                  <el-icon><CircleClose /></el-icon>
                  {{ $t('authorizations.revoke') }}
                </el-button>
                <el-text
                  v-else-if="row.source === 'ticket'"
                  size="small"
                  type="info"
                >
                  {{ row.validity_state === 'scheduled' ? $t('authorizations.scheduled') : $t('authorizations.expired') }}
                </el-text>
                <el-button
                  v-else
                  type="danger"
                  size="small"
                  link
                  @click="handleDelete(row)"
                >
                  <el-icon><Delete /></el-icon>
                  {{ $t('common.delete') }}
                </el-button>
              </template>
            </el-table-column>
            <template #empty>
              <EmptyState
                v-if="!loadError"
                :title="$t('authorizations.emptyTitle')"
                :hint="$t('authorizations.emptyHint')"
              />
              <span v-else />
            </template>
          </el-table>

          <!-- 分頁 -->
          <div class="pagination">
            <el-pagination
              v-model:current-page="pagination.page"
              v-model:page-size="pagination.page_size"
              :page-sizes="[10, 20, 50, 100]"
              :total="pagination.total"
              layout="total, sizes, prev, pager, next, jumper"
              @size-change="handleSizeChange"
              @current-change="handlePageChange"
            />
          </div>
        </div>
      </el-tab-pane>

      <el-tab-pane
        :label="$t('authorizations.tabSubject')"
        name="subject"
        lazy
      >
        <div class="list-card">
          <AuthzEffectiveView mode="subject" />
        </div>
      </el-tab-pane>
      <el-tab-pane
        :label="$t('authorizations.tabObject')"
        name="object"
        lazy
      >
        <div class="list-card">
          <AuthzEffectiveView mode="object" />
        </div>
      </el-tab-pane>
    </el-tabs>

    <!-- 批次授權精靈（D6 拆檔；node_id 深連結預填經 prop 傳遞） -->
    <AuthzBatchWizard
      v-model="batchDialogVisible"
      :prefill-node-id="prefillNodeId"
      @completed="fetchAuthorizationList"
    />

    <!-- ticket 撤銷確認（走 Change 2b 申請單撤銷 API，含斷線聯動語義） -->
    <el-dialog
      v-model="revokeDialogVisible"
      :title="$t('authorizations.revokeDialogTitle')"
      width="480px"
      :close-on-click-modal="false"
    >
      <el-alert
        type="warning"
        :closable="false"
        show-icon
        style="margin-bottom: 16px"
        :title="$t('authorizations.revokeAlert')"
      />
      <el-form label-position="top">
        <el-form-item
          :label="$t('authorizations.revokeReasonLabel')"
          required
        >
          <el-input
            v-model="revokeNote"
            type="textarea"
            :rows="3"
            maxlength="200"
            show-word-limit
            :placeholder="$t('authorizations.revokePlaceholder')"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="revokeDialogVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="warning"
          :loading="revokeSubmitting"
          :disabled="!revokeNote.trim()"
          @click="submitRevoke"
        >
          {{ $t('common.confirmRevoke') }}
        </el-button>
      </template>
    </el-dialog>

    <!-- 帳號範圍調整（asset-multi-account D5） -->
    <AuthzAccountScopeDialog
      v-model="accountScopeVisible"
      :row="accountScopeRow"
      @saved="fetchAuthorizationList"
    />
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  Plus,
  Refresh,
  Search,
  Delete,
  CircleClose,
  QuestionFilled,
  Key,
} from '@element-plus/icons-vue'
import { useRoute } from 'vue-router'
import { getAuthorizations, deleteAuthorization } from '@/api/authorizations'
import { revokeAccessRequest } from '@/api/accessRequests'
import { getUserGroups } from '@/api/userGroups'
import { getUsers } from '@/api/auth'
import { getAssetList, getAssetGroups } from '@/api/assets'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import AuthzBatchWizard from '@/components/AuthzBatchWizard.vue'
import AuthzEffectiveView from '@/components/AuthzEffectiveView.vue'
import AuthzAccountScopeDialog from '@/components/AuthzAccountScopeDialog.vue'
import { isAllAccountScope } from '@/constants/assetAccounts'
import { formatDateTime } from '@/utils/format'
import { useRoles } from '@/composables/useRoles'
import { t } from '@/i18n'
import { resolveApiError } from '@/api/error'

// 資料狀態
const loading = ref(false)
const loadError = ref('')
const authorizationList = ref([])
const userList = ref([])
const assetList = ref([])
const userGroupList = ref([])
const pagination = reactive({
  page: 1,
  page_size: 20,
  total: 0,
})
const activeTab = ref('records')

// 使用者角色檢查
const { isAdmin } = useRoles()

// 過濾表單（user_id / user_group_id / asset_id / node_id 至多一個；
// 零篩選＝全量，D1；node_id＝涵蓋盤點語義，authz-tag-node-filters D7）
const filterForm = reactive({
  user_id: '',
  user_group_id: '',
  asset_id: '',
  node_id: '',
})

// 快速篩選 chip → 伺服端 validity/source 參數（D7）
const quickFilter = ref('all')
const quickFilterParams = () => {
  switch (quickFilter.value) {
    case 'active':
      return { validity: 'active' }
    case 'expired':
      return { validity: 'expired' }
    case 'ticket':
      return { source: 'ticket' }
    default:
      return {}
  }
}

// 四過濾器互斥：選定一個即清空其他三個
const handleSubjectFilterChange = (field) => {
  if (filterForm[field] !== '' && filterForm[field] !== null && filterForm[field] !== undefined) {
    for (const key of ['user_id', 'user_group_id', 'asset_id', 'node_id']) {
      if (key !== field) filterForm[key] = ''
    }
  }
  handleFilter()
}

// 取得授權列表：實送分頁參數；失敗顯錯不偽裝空狀態（D1）
const fetchAuthorizationList = async () => {
  loading.value = true
  loadError.value = ''
  try {
    const params = {
      user_id: filterForm.user_id || undefined,
      user_group_id: filterForm.user_group_id || undefined,
      asset_id: filterForm.asset_id || undefined,
      node_id: filterForm.node_id || undefined,
      page: pagination.page,
      page_size: pagination.page_size,
      ...quickFilterParams(),
    }

    const response = await getAuthorizations(params)
    authorizationList.value = response.data || []
    pagination.total = response.total || 0
  } catch (error) {
    console.error('取得授權列表失敗:', error)
    authorizationList.value = []
    pagination.total = 0
    loadError.value = resolveApiError(
      error?.response?.data,
      error?.response?.status,
      t('common.serverError')
    )
  } finally {
    loading.value = false
  }
}

const fetchUserList = async () => {
  try {
    const response = await getUsers()
    userList.value = response.data || []
  } catch (error) {
    console.error('取得使用者列表失敗:', error)
  }
}

const fetchAssetList = async () => {
  try {
    const response = await getAssetList({ page_size: 1000 })
    assetList.value = response.data || []
  } catch (error) {
    console.error('取得資產列表失敗:', error)
  }
}

// 節點樹選項（authz-tag-node-filters D7 篩選用）：平面列表組樹，
// 與精靈 nodeTreeOptions 同型轉換
const groupList = ref([])
const loadGroupList = async () => {
  try {
    const res = await getAssetGroups()
    groupList.value = res.data || []
  } catch (err) {
    console.error('載入節點清單失敗:', err)
  }
}
const nodeTreeOptions = computed(() => {
  const byId = new Map()
  groupList.value.forEach((n) => {
    byId.set(n.id, { id: n.id, name: n.name, label: n.name, parent_id: n.parent_id, children: [] })
  })
  const roots = []
  byId.forEach((n) => {
    if (n.parent_id && byId.has(n.parent_id)) {
      byId.get(n.parent_id).children.push(n)
    } else {
      roots.push(n)
    }
  })
  return roots
})

const loadUserGroupList = async () => {
  try {
    const res = await getUserGroups()
    userGroupList.value = res.data || []
  } catch (err) {
    console.error('載入使用者群組失敗:', err)
  }
}

// 篩選/快速篩選/每頁筆數變更一律重設頁碼（codex M7：否則伺服端正確回
// 空的第 N 頁，重現偽空狀態）
const handleFilter = () => {
  pagination.page = 1
  fetchAuthorizationList()
}

const handleQuickFilterChange = () => {
  pagination.page = 1
  fetchAuthorizationList()
}

const handleResetFilter = () => {
  filterForm.user_id = ''
  filterForm.user_group_id = ''
  filterForm.asset_id = ''
  filterForm.node_id = ''
  quickFilter.value = 'all'
  pagination.page = 1
  fetchAuthorizationList()
}

const handleRefresh = () => {
  fetchAuthorizationList()
}

const handleSizeChange = () => {
  pagination.page = 1
  fetchAuthorizationList()
}

const handlePageChange = () => {
  fetchAuthorizationList()
}


// 權限標籤
const getPermissionTagType = (permission) => {
  const typeMap = { view: 'info', connect: 'success' }
  return typeMap[permission] || 'info'
}
const getPermissionText = (permission) => {
  const textMap = { view: t('assets.permission.view'), connect: t('assets.permission.connect') }
  return textMap[permission] || permission
}

// 非 active 列整列灰化：過期／未生效的授權仍留在列表中，靠整列底色與生效中的列區隔
const rowClassName = ({ row }) => {
  if (row.validity_state && row.validity_state !== 'active') {
    return 'authz-row-inactive'
  }
  return ''
}

// 到期時間三色（>7 天綠 / ≤7 天黃 / 過期紅）：7 天是「該續期了」的提前量
const expiryClass = (row) => {
  if (!row.date_expired) return ''
  const remain = new Date(row.date_expired).getTime() - Date.now()
  if (remain <= 0) return 'expiry-expired'
  if (remain <= 7 * 24 * 3600 * 1000) return 'expiry-soon'
  return 'expiry-ok'
}

// 刪除（manual；ticket 有單者伺服端 409 守門）
const handleDelete = async (row) => {
  const subject = row.user_group_name
    ? t('authorizations.deleteSubjectGroup', { name: row.user_group_name })
    : t('authorizations.deleteSubjectUser', { name: row.username })
  const target = row.asset_group_name
    ? t('authorizations.deleteTargetNode', { name: row.asset_group_name })
    : t('authorizations.deleteTargetAsset', { name: row.asset_name })
  try {
    await ElMessageBox.confirm(
      t('authorizations.deleteConfirm', { subject, target }),
      t('common.deleteConfirmTitle'),
      {
        confirmButtonText: t('common.deleteConfirmButton'),
        cancelButtonText: t('common.cancel'),
        type: 'warning',
      }
    )
  } catch {
    return // 使用者取消
  }

  try {
    await deleteAuthorization(row.id)
    ElMessage.success(t('authorizations.deleted'))
    fetchAuthorizationList()
  } catch (error) {
    // 409＝ticket 裸刪守門：提示走撤銷流
    if (error?.response?.status === 409) {
      ElMessage.error(
        resolveApiError(error.response?.data, 409, t('authorizations.ticketDeleteHint'))
      )
    }
    console.error('刪除失敗:', error)
  }
}

// 帳號範圍調整（asset-multi-account D5）
const accountScopeVisible = ref(false)
const accountScopeRow = ref(null)

const openAccountScope = (row) => {
  accountScopeRow.value = row
  accountScopeVisible.value = true
}

// ticket 撤銷（D4：借道 Change 2b 申請單撤銷 API，資格/附註/斷線聯動零新語義）
const revokeDialogVisible = ref(false)
const revokeSubmitting = ref(false)
const revokeNote = ref('')
const revokeTarget = ref(null)

const handleRevoke = (row) => {
  revokeTarget.value = row
  revokeNote.value = ''
  revokeDialogVisible.value = true
}

const submitRevoke = async () => {
  if (!revokeTarget.value?.request_id) return
  revokeSubmitting.value = true
  try {
    await revokeAccessRequest(revokeTarget.value.request_id, revokeNote.value.trim())
    ElMessage.success(t('authorizations.revoked'))
    revokeDialogVisible.value = false
    fetchAuthorizationList()
  } catch (error) {
    // 全域攔截器已 toast 錯誤（C10：頁內不重複）
    console.error('撤銷失敗:', error)
  } finally {
    revokeSubmitting.value = false
  }
}

// 批次授權精靈
const route = useRoute()
const batchDialogVisible = ref(false)
const prefillNodeId = ref(null)

const handleBatchAuthorize = () => {
  prefillNodeId.value = null
  batchDialogVisible.value = true
}

// 掛載時取得資料
onMounted(() => {
  fetchAuthorizationList()
  fetchUserList()
  fetchAssetList()
  loadUserGroupList()
  loadGroupList()

  // 資產/節點視角授權入口（asset-node-tree D5）：自資產頁樹「授權此節點」
  // 跳轉預填——開精靈並經 prop 傳入節點 id，由精靈於清單落地後預勾
  //（route 可為 undefined：單測掛載無 router）
  const nodeIDRaw = route?.query?.node_id
  if (nodeIDRaw && isAdmin.value) {
    prefillNodeId.value = Number(nodeIDRaw)
    batchDialogVisible.value = true
  }
})
</script>

<style scoped>
.node-filter-help {
  margin-left: 4px;
  color: var(--el-text-color-secondary);
  cursor: help;
  vertical-align: middle;
}

.authorizations {
  /* MainLayout main-content 已有 padding，此處不重複加 */
}

.target-group-tag {
  margin-right: 6px;
}

.account-scope-tag {
  margin: 0 6px 4px 0;
  font-family: var(--ot-font-mono, monospace);
}

.deleted-entity {
  color: var(--ot-text-secondary);
  font-style: italic;
}

.filter-bar {
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  margin-bottom: var(--ot-space-md);
}

.quick-filters {
  margin-top: var(--ot-space-sm);
}

.list-card {
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  min-height: 400px;
}

.load-error {
  margin-bottom: var(--ot-space-md);
}

.pagination {
  margin-top: var(--ot-space-md);
  display: flex;
  justify-content: flex-end;
}

.source-permanent {
  color: var(--ot-text-secondary);
  font-size: 13px;
}

.expiry-line {
  font-size: 12px;
  margin-top: 2px;
}

.expiry-ok {
  color: var(--el-color-success);
}

.expiry-soon {
  color: var(--el-color-warning);
}

.expiry-expired {
  color: var(--el-color-danger);
}

/* 非 active 列整列灰化（scheduled/expired 分態標示、樣式同灰） */
:deep(.authz-row-inactive) {
  opacity: 0.55;
}
</style>
