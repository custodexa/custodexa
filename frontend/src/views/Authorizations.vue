<template>
  <div class="authorizations">
    <PageHeader
      :title="$t('authorizations.title')"
      :description="$t('authorizations.headerDesc')"
    >
      <template
        v-if="authzScopeLine"
        #meta
      >
        <ManageScopeLine
          :nodes="authzScopeLine.nodes"
          :not-assigned="authzScopeLine.notAssigned"
        />
      </template>
      <template #actions>
        <el-button
          v-if="canManageAuthorizations && activeTab !== 'policy'"
          type="primary"
          @click="handleBatchAuthorize"
        >
          <el-icon><Plus /></el-icon>
          {{ $t('authorizations.batchAuthorize') }}
        </el-button>
        <el-button @click="handleRefresh">
          <el-icon><RefreshCw /></el-icon>
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
                  :label="userOptionLabel(user)"
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
            <!-- 節點涵蓋盤點：第四個互斥維度 -->
            <el-form-item>
              <template #label>
                <span>{{ $t('common.node') }}</span>
                <el-tooltip
                  placement="top"
                  :content="$t('authorizations.filterNodeHelp')"
                >
                  <el-icon class="node-filter-help">
                    <CircleQuestionMark />
                  </el-icon>
                </el-tooltip>
              </template>
              <el-select
                v-model="filterForm.node_id"
                clearable
                filterable
                :placeholder="$t('authorizations.allNodes')"
                style="width: 200px"
                @change="handleSubjectFilterChange('node_id')"
              >
                <el-option
                  v-for="n in nodeOptions"
                  :key="n.id"
                  :label="n.path"
                  :value="n.id"
                  :disabled="!isSelectableNode(n)"
                />
              </el-select>
            </el-form-item>
            <el-form-item v-if="selectorFailed">
              <el-text
                type="warning"
                size="small"
                class="selector-failed"
              >
                {{ $t('authorizations.selectorLoadFailed') }}
              </el-text>
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
                <el-icon><RefreshCw /></el-icon>
                {{ $t('common.reset') }}
              </el-button>
            </el-form-item>
          </el-form>

          <!-- 快速篩選 chip（對應伺服端 validity/source 參數，跨頁正確） -->
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
            <!-- 帳號範圍：預設全部帳號，可個別指定 username -->
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
                <!-- 動作依伺服器回的 actions 判定（非超級管理者）；沒有 actions 時沿現行邏輯。
                     帳號範圍僅 manual 列可改：ticket 列的範圍源自申請單，於此改等於繞過申請與核准 -->
                <el-tooltip
                  v-if="row.source !== 'ticket'"
                  :disabled="!accountScopeView(row).note"
                  :content="accountScopeView(row).note"
                  placement="top"
                >
                  <span class="account-scope-wrap">
                    <el-button
                      type="primary"
                      size="small"
                      link
                      :disabled="accountScopeView(row).disabled"
                      @click="openAccountScope(row)"
                    >
                      <el-icon><Key /></el-icon>
                      {{ $t('authorizations.accountScopeAction') }}
                    </el-button>
                  </span>
                </el-tooltip>
                <!-- ticket 列只有撤銷：可撤走申請單撤銷流，不可撤者停用並說明原因，
                     過期/未生效唯讀留存（審計證據）；manual 照常刪除 -->
                <template v-if="row.source === 'ticket'">
                  <el-tooltip
                    v-if="revokeView(row).kind !== 'status'"
                    :disabled="!revokeView(row).note"
                    :content="revokeView(row).note"
                    placement="top"
                  >
                    <span class="account-scope-wrap">
                      <el-button
                        type="warning"
                        size="small"
                        link
                        :disabled="revokeView(row).kind === 'disabled'"
                        @click="handleRevoke(row)"
                      >
                        <el-icon><CircleX /></el-icon>
                        {{ $t('authorizations.revoke') }}
                      </el-button>
                    </span>
                  </el-tooltip>
                  <el-text
                    v-else
                    size="small"
                    type="info"
                  >
                    {{ row.validity_state === 'scheduled' ? $t('authorizations.scheduled') : $t('authorizations.expired') }}
                  </el-text>
                </template>
                <el-tooltip
                  v-else
                  :disabled="!deleteView(row).note"
                  :content="deleteView(row).note"
                  placement="top"
                >
                  <span class="account-scope-wrap">
                    <el-button
                      type="danger"
                      size="small"
                      link
                      :disabled="deleteView(row).disabled"
                      @click="handleDelete(row)"
                    >
                      <el-icon><Trash2 /></el-icon>
                      {{ $t('common.delete') }}
                    </el-button>
                  </span>
                </el-tooltip>
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
      <!-- 連線政策分頁：持存取政策權限點才出現，切到才載入，內容與存取管控頁同一元件 -->
      <el-tab-pane
        v-if="canManageAccessPolicy"
        :label="$t('authorizations.tabAccessPolicy')"
        name="policy"
        lazy
      >
        <div class="list-card">
          <AssetPolicyTable ref="policyTableRef" />
        </div>
      </el-tab-pane>
    </el-tabs>

    <!-- 批次授權精靈（node_id 深連結預填經 prop 傳遞） -->
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

    <!-- 帳號範圍調整 -->
    <AuthzAccountScopeDialog
      v-model="accountScopeVisible"
      :row="accountScopeRow"
      :narrow-only="accountScopeNarrowOnly"
      @saved="fetchAuthorizationList"
    />
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  Plus,
  RefreshCw,
  Search,
  Trash2,
  CircleX,
  CircleQuestionMark,
  Key,
} from 'lucide-vue-next'
import { useRoute } from 'vue-router'
import {
  getAuthorizations,
  deleteAuthorization,
  getSelfSubjects,
  getAuthorizationSubjectOptions,
  getAuthorizationTargetOptions,
} from '@/api/authorizations'
import { revokeAccessRequest } from '@/api/accessRequests'
import PageHeader from '@/components/PageHeader.vue'
import ManageScopeLine from '@/components/ManageScopeLine.vue'
import { useManageScopeLine } from '@/composables/useManageScope'
import EmptyState from '@/components/EmptyState.vue'
import AuthzBatchWizard from '@/components/AuthzBatchWizard.vue'
import AuthzEffectiveView from '@/components/AuthzEffectiveView.vue'
import AssetPolicyTable from '@/components/AssetPolicyTable.vue'
import AuthzAccountScopeDialog from '@/components/AuthzAccountScopeDialog.vue'
import { isAllAccountScope } from '@/constants/assetAccounts'
import { formatDateTime } from '@/utils/format'
import { can } from '@/composables/useCapabilities'
import { ACCESS_POLICY_PERM } from '@/utils/accessPolicyTier'
import { t } from '@/i18n'
import { resolveApiError } from '@/api/error'
import { actionState, isSelectableNode, loadSelector, userOptionLabel } from '@/utils/authzSelectors'

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
// 頁首範圍行：連線政策分頁取存取政策權限點，其餘授權規則分頁取授權規則管理權限點
const authzScopeLine = useManageScopeLine(() => (activeTab.value === 'policy' ? 'access_policy:manage' : 'authorization:manage'))
const policyTableRef = ref(null)

// 使用者角色檢查
// 批次授權與節點預填都是 authorization:manage 的操作（後端才是強制點）
const canManageAuthorizations = computed(() => can('authorization:manage'))
// 連線政策分頁只看存取政策權限點；範圍由後端依指派投影
const canManageAccessPolicy = computed(() => can(ACCESS_POLICY_PERM))

// 過濾表單（user_id / user_group_id / asset_id / node_id 至多一個；
// 零篩選＝全量；node_id＝涵蓋盤點語義）
const filterForm = reactive({
  user_id: '',
  user_group_id: '',
  asset_id: '',
  node_id: '',
})

// 快速篩選 chip → 伺服端 validity/source 參數
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

// 取得授權列表：實送分頁參數；失敗顯錯不偽裝空狀態
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

// 篩選下拉的四個來源分開載入（授權管理選擇器，已依伺服器端範圍投影）；
// 任一來源失敗時其餘清單仍有值，失敗就地提示
const selectorFailed = ref(false)
const nodeOptions = ref([])
const loadFilterOptions = async () => {
  const [users, groups, assets, nodes] = await Promise.all([
    loadSelector(getAuthorizationSubjectOptions, { kind: 'user' }),
    loadSelector(getAuthorizationSubjectOptions, { kind: 'user_group' }),
    loadSelector(getAuthorizationTargetOptions, { kind: 'asset' }),
    loadSelector(getAuthorizationTargetOptions, { kind: 'node' }),
  ])
  userList.value = users.rows
  userGroupList.value = groups.rows
  assetList.value = assets.rows
  nodeOptions.value = nodes.rows
  selectorFailed.value = [users, groups, assets, nodes].some((r) => r.failed)
}

// 篩選/快速篩選/每頁筆數變更一律重設頁碼（否則伺服端正確回
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
  if (activeTab.value === 'policy') {
    policyTableRef.value?.reload?.()
    return
  }
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

// 帳號範圍調整
const accountScopeVisible = ref(false)
const accountScopeRow = ref(null)
const accountScopeNarrowOnly = ref(false)

// 列動作的畫面狀態：有伺服器回的 actions 就照它，沒有（超級管理者）沿現行邏輯
const accountScopeView = (row) => {
  const st = actionState(row, 'update_accounts', t)
  if (st) return { disabled: !st.allowed, note: st.note, narrowOnly: st.limit === 'narrow_only' }
  const self = isSelfSubjectRow(row)
  return { disabled: self, note: self ? t('authorizations.accountScopeSelfLocked') : '', narrowOnly: false }
}
const deleteView = (row) => {
  const st = actionState(row, 'delete', t)
  if (st) return { disabled: !st.allowed, note: st.note }
  return { disabled: false, note: '' }
}
// ticket 列：enabled＝可撤銷；disabled＝停用並說明；status＝唯讀狀態文字（已到期／未生效）
const revokeView = (row) => {
  const st = actionState(row, 'revoke', t)
  if (st) {
    if (st.allowed) return { kind: 'enabled', note: '' }
    if (st.reason === 'not_revocable' && row.validity_state && row.validity_state !== 'active') {
      return { kind: 'status', note: '' }
    }
    return { kind: 'disabled', note: st.note }
  }
  return row.revocable ? { kind: 'enabled', note: '' } : { kind: 'status', note: '' }
}
const openAccountScope = (row) => {
  const view = accountScopeView(row)
  if (view.disabled) return
  accountScopeRow.value = row
  accountScopeNarrowOnly.value = view.narrowOnly
  accountScopeVisible.value = true
}

// 本人範圍（與後端守衛同一判定）：主體為本人、本人擁有的 agent 或本人所屬群組的列，
// 帳號範圍動作停用；刪除與臨時授權的撤銷不變。端點失敗或超管 applies=false 時不停用
const selfSubjects = ref(null)
const isSelfSubjectRow = (row) => {
  const s = selfSubjects.value
  if (!s?.applies || !row) return false
  if (row.user_id && (row.user_id === s.user_id || (s.agent_ids || []).includes(row.user_id))) return true
  return Boolean(row.user_group_id && (s.user_group_ids || []).includes(row.user_group_id))
}
const loadSelfSubjects = async () => {
  try {
    selfSubjects.value = await getSelfSubjects()
  } catch (err) {
    selfSubjects.value = null
  }
}

// ticket 撤銷（借道 Change 2b 申請單撤銷 API，資格/附註/斷線聯動零新語義）
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
  loadSelfSubjects()
  fetchAuthorizationList()
  loadFilterOptions()

  // 資產/節點視角授權入口：自資產頁樹「授權此節點」
  // 跳轉預填——開精靈並經 prop 傳入節點 id，由精靈於清單落地後預勾
  //（route 可為 undefined：單測掛載無 router）
  const nodeIDRaw = route?.query?.node_id
  if (nodeIDRaw && canManageAuthorizations.value) {
    prefillNodeId.value = Number(nodeIDRaw)
    batchDialogVisible.value = true
  }
})
</script>

<style scoped>
.account-scope-wrap {
  display: inline-flex;
  margin-right: 8px;
}
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
