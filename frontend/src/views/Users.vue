<template>
  <div class="users">
    <PageHeader
      :title="$t('menu.users')"
      :description="$t('users.headerDesc')"
    >
      <template #actions>
        <el-button
          type="primary"
          @click="handleCreate"
        >
          <el-icon><Plus /></el-icon>
          {{ $t('users.create') }}
        </el-button>
        <el-button @click="handleRefresh">
          <el-icon><RefreshCw /></el-icon>
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>

    <!-- 篩選面板 -->
    <div class="filter-bar">
      <el-form
        :inline="true"
        :model="filterForm"
      >
        <el-form-item :label="$t('agentPrincipals.kind')">
          <el-select
            v-model="filterForm.kind"
            clearable
            :placeholder="$t('common.all')"
            data-test="principal-kind-filter"
            style="width: 160px"
            @change="handleKindChange"
          >
            <el-option
              value="human"
              :label="$t('agentPrincipals.human')"
            />
            <el-option
              value="agent"
              :label="$t('agentPrincipals.agent')"
            />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('common.search')">
          <el-input
            v-model="filterForm.search"
            :placeholder="$t('users.searchPlaceholder')"
            clearable
            style="width: 250px"
            @clear="handleFilter"
            @keyup.enter="handleFilter"
          >
            <template #prefix>
              <el-icon><Search /></el-icon>
            </template>
          </el-input>
        </el-form-item>
        <el-form-item :label="$t('common.status')">
          <el-select
            v-model="filterForm.active"
            :placeholder="$t('common.all')"
            clearable
            style="width: 120px"
            @change="handleFilter"
          >
            <el-option
              :label="$t('common.enabled')"
              :value="true"
            />
            <el-option
              :label="$t('common.disabled')"
              :value="false"
            />
          </el-select>
        </el-form-item>
        <!-- 供應來源篩選：伺服端篩選。
             列表是分頁的，在前端篩當頁會讓使用者看到「第 2 頁明明有 oidc 帳號，
             篩選後卻說沒有」 -->
        <el-form-item :label="$t('users.sourceColumn')">
          <el-select
            v-model="filterForm.provisioningOrigin"
            :placeholder="$t('common.all')"
            clearable
            style="width: 140px"
            @change="handleFilter"
          >
            <el-option
              v-for="origin in KNOWN_AUTH_SOURCES"
              :key="origin"
              :label="$t(`enum.authSource.${origin}`)"
              :value="origin"
            />
          </el-select>
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
    </div>

    <!-- 用戶列表 -->
    <div class="list-card">
      <!-- 欄寬預算——
           先算再排，不逐欄補丁：1280 視窗下本頁表格可視寬約 978px，
           下列宣告寬總和 918（46+70+180+140+130+112+240）必須守在該值內，
           因此不會產生橫向捲軸，也就沒有任何欄位被浮層蓋住的可能。
           取捨：次要欄（Email／全名／閒置豁免／最後登入／建立時間）改由展開列
           承載——它們都不是「橫向掃一眼判斷這個帳號是誰、能不能登入」所需；
           操作欄只留三項，其餘進「更多」。
           操作欄寬取三語最寬者（en「External Identities」）定寬。
           **新增欄位前先重算這條加總**；加不進去就再往展開列收，不要動 fixed。 -->
      <el-table
        v-loading="loading"
        v-expand-row-a11y
        :data="userList"
        style="width: 100%"
        stripe
        :default-sort="{ prop: 'id', order: 'ascending' }"
      >
        <!-- 展開列承載次要欄位：留在主表會把總寬推到 1890（1280 下需橫捲近一倍），
             而 macOS 覆蓋式捲軸不提示右邊還有欄位 -->
        <el-table-column
          type="expand"
          width="46"
        >
          <template #default="{ row }">
            <div class="row-detail">
              <div class="row-detail__item">
                <span class="row-detail__label">Email</span>
                <span class="row-detail__value">{{ row.email || '—' }}</span>
              </div>
              <div class="row-detail__item">
                <span class="row-detail__label">{{ $t('users.fullName') }}</span>
                <span class="row-detail__value">{{ row.full_name || '—' }}</span>
              </div>
              <!-- 最近登入已移到主表的狀態欄第二行，此處不重複 -->
              <div class="row-detail__item">
                <span class="row-detail__label">{{ $t('common.createdAt') }}</span>
                <span class="row-detail__value">{{ formatDateTime(row.created_at) }}</span>
              </div>
              <!-- 閒置豁免是**控制項**不是資訊，收進展開列仍須可直接操作 -->
              <div class="row-detail__item">
                <el-tooltip
                  :content="$t('users.inactivityExemptTooltip')"
                  placement="top"
                >
                  <span class="row-detail__label col-header-hint">
                    {{ $t('users.inactivityExempt') }}
                  </span>
                </el-tooltip>
                <span class="row-detail__value">
                  <el-space :size="6">
                    <el-switch
                      v-model="row.inactivity_exempt"
                      :loading="row._exemptLoading"
                      :aria-label="$t('users.toggleExemptAria', { name: row.username })"
                      @change="handleExemptChange(row)"
                    />
                    <el-tag
                      v-if="row.inactivity_exempt"
                      type="info"
                      size="small"
                    >
                      <el-icon><CircleCheck /></el-icon>
                      {{ $t('users.exempt') }}
                    </el-tag>
                  </el-space>
                </span>
              </div>
            </div>
          </template>
        </el-table-column>
        <!-- 編號欄不放裸數字：一格單獨的「31」在稽核截圖上讀不出是什麼的編號。
             欄頭用中性的「編號」，值帶類型（使用者 31）。
             加寬 40px（70→110）後欄寬總和仍守在可視寬內 -->
        <el-table-column
          prop="id"
          :label="$t('common.idColumn')"
          width="110"
          sortable
        >
          <template #default="{ row }">
            {{ $t('common.userRef', { id: row.id }) }}
          </template>
        </el-table-column>
        <el-table-column
          prop="username"
          :label="$t('common.username')"
          min-width="180"
        >
          <template #default="{ row }">
            <a
              class="cell-main user-link"
              data-test="user-link"
              :href="`/users/${row.id}`"
              @click.prevent="openDetail(row)"
            >{{ row.username }}</a>
            <!-- 全名以副行呈現：省下一整欄，且「這是誰」本來就該與帳號同讀 -->
            <div
              v-if="row.full_name"
              class="cell-sub"
            >
              {{ row.full_name }}
            </div>
          </template>
        </el-table-column>
        <!-- 主體類型連帶顯示負責人帳號名：130px 時「負責人：xxx」折成兩行，
             與同列的使用者名稱基線對不齊 -->
        <el-table-column
          :label="$t('agentPrincipals.kind')"
          min-width="190"
        >
          <template #default="{ row }">
            <PrincipalBadge
              :kind="row.kind"
              :owner-id="row.owner_user_id"
              :owner-name="row.owner_username"
            />
          </template>
        </el-table-column>
        <!-- 帳號來源：供應來源為權威欄位，
             不由 is_ldap 推導——OIDC 供應帳號的 is_ldap 為 false，只認該欄
             會把外部帳號一律顯示成本地帳號。
             位置緊接使用者名稱：擺在 email/全名之後時，
             1280 寬度下這欄落在 fixed 操作欄的覆蓋範圍內，本輪最重要的新資訊
             預設看不到，而 macOS 覆蓋式捲軸不會提示右邊還有欄位 -->
        <el-table-column
          :label="$t('users.sourceColumn')"
          min-width="140"
        >
          <template #header>
            <el-tooltip
              :content="$t('users.sourceColumnTooltip')"
              placement="top"
            >
              <span class="col-header-hint">{{ $t('users.sourceColumn') }}</span>
            </el-tooltip>
          </template>
          <template #default="{ row }">
            <el-tag
              size="small"
              effect="plain"
            >
              {{ sourceLabel(row) }}
            </el-tag>
            <!-- provider 實例名：多 provider 並存下，「這個人從哪個 IdP 來」
                 才是管理者要看的；只顯示籠統的「OIDC」無從判斷解綁影響面。
                 綁多個時全部列出——只顯示第一個會讓人誤以為解綁一個就切斷全部途徑 -->
            <el-tag
              v-for="name in (row.auth_provider_names || [])"
              :key="name"
              size="small"
              type="info"
              effect="plain"
              class="source-provider-tag"
            >
              {{ name }}
            </el-tag>
          </template>
        </el-table-column>
        <!-- 角色欄同時回答「有哪些角色」與「這個角色是誰給的」。
             後者不可省：撤走一個角色的方法依來源而不同——管理者指派的在本頁改，
             映射賦予的要改目錄側的群組或映射規則，只顯示角色名會讓人在本頁
             反覆嘗試一個不會生效的操作 -->
        <el-table-column
          :label="$t('common.role')"
          min-width="150"
        >
          <template #default="{ row }">
            <el-space wrap>
              <span
                v-for="role in (row.roles || [])"
                :key="role.id || role.name || role"
                class="role-cell"
              >
                <el-tag
                  :type="roleTagType(role.name || role)"
                  size="small"
                >
                  {{ roleLabel(role.name || role) }}
                </el-tag>
                <el-tag
                  v-if="roleSourceOf(row, role.name || role)"
                  size="small"
                  type="info"
                  effect="plain"
                  class="role-source-tag"
                  :data-test="`role-source-${role.name || role}`"
                >
                  {{ $t(`users.roleSource.${roleSourceOf(row, role.name || role)}`) }}
                </el-tag>
              </span>
              <!-- 「無角色」是事實敘述而非狀態，不佔用品牌青（身分徽章同色） -->
              <el-tag
                v-if="!row.roles || row.roles.length === 0"
                class="ot-tag-neutral"
                size="small"
              >
                {{ $t('users.noRole') }}
              </el-tag>
              <!-- 映射賦予的審核者角色不會連帶產生審核範圍：沒有範圍的審核者
                   在申請流程上收不到任何案件，而畫面上看起來一切正常 -->
              <el-tooltip
                v-if="needsApproverScope(row)"
                :content="$t('users.mappedApproverNeedsScopeTooltip')"
                placement="top"
              >
                <el-tag
                  type="warning"
                  size="small"
                  effect="plain"
                  data-test="mapped-approver-needs-scope"
                >
                  {{ $t('users.mappedApproverNeedsScope') }}
                </el-tag>
              </el-tooltip>
            </el-space>
          </template>
        </el-table-column>
        <!-- 狀態欄承載「這個帳號能不能登入」的三件事：啟用、鎖定、來源限定。
             來源限定不另立一欄：本表欄寬預算（見上方註解）在 1280 下只剩
             60px 餘裕，加一欄會把總寬推過可視寬而產生橫捲。
             112 → 150 後總和 956，仍守在 978 內 -->
        <el-table-column
          :label="$t('common.status')"
          width="150"
        >
          <template #default="{ row }">
            <el-space
              :size="6"
              wrap
            >
              <el-switch
                v-model="row.active"
                :loading="row._statusLoading"
                :aria-label="$t('users.toggleActiveAria', { name: row.username })"
                @change="handleStatusChange(row)"
              />
              <el-tooltip
                v-if="isLocked(row)"
                :content="$t('users.lockedUntil', { time: formatDateTime(row.locked_until) })"
                placement="top"
              >
                <el-tag
                  type="danger"
                  size="small"
                >
                  <el-icon><Lock /></el-icon>
                  {{ $t('users.locked') }}
                </el-tag>
              </el-tooltip>
              <!-- 三態消費伺服端衍生的 allowed_cidrs_status，**不以陣列非空推算**：
                   清單含 0.0.0.0/0 時實際全部放行，標成「已限定」是把放行呈為受限。
                   不限（unrestricted）不標示——沒有限制不是一種狀態 -->
              <el-tooltip
                v-if="row.allowed_cidrs_status === 'restricted'"
                :content="$t('users.allowedCidrsTagRestrictedTooltip')"
                placement="top"
              >
                <el-tag
                  type="info"
                  size="small"
                  data-test="source-restricted-tag"
                >
                  {{ $t('users.allowedCidrsTagRestricted') }}
                </el-tag>
              </el-tooltip>
              <el-tooltip
                v-else-if="row.allowed_cidrs_status === 'effectively_unrestricted'"
                :content="effectiveUnrestrictedText(row.allowed_cidrs_families)"
                placement="top"
              >
                <el-tag
                  type="warning"
                  size="small"
                  data-test="source-effective-tag"
                >
                  {{ $t('users.allowedCidrsTagEffective') }}
                </el-tag>
              </el-tooltip>
            </el-space>
            <!-- 最近登入放在狀態欄第二行而非另立一欄：欄寬預算在 1280 下已無餘裕。
                 它進主表的理由是撤權時效——映射角色要到下次登入才重算，
                 「這個人上次什麼時候登入」是判斷一條映射改動生效與否的第一個線索 -->
            <div
              class="cell-subline"
              data-test="last-login-line"
            >
              {{ row.last_login_at
                ? $t('users.lastLoginAt', { time: formatDateTime(row.last_login_at) })
                : $t('users.neverLoggedIn') }}
            </div>
          </template>
        </el-table-column>
        <!-- 操作欄**不再 fixed**：fixed 欄是浮在內容上的浮層，
             一旦總寬超出可視寬就會靜默蓋掉右側資料欄——先前把它從 470 縮到 280
             只換回 190px，1280 下角色與狀態仍是 100% 被覆蓋。與其逐欄前移，
             不如讓表格根本不橫捲：欄寬總和已收在可視寬內，fixed 沒有存在意義，
             留著只是把同一個缺陷留給下一次「再加一欄」 -->
        <el-table-column
          :label="$t('common.actions')"
          width="240"
        >
          <template #default="{ row }">
            <UserAccountActions
              :row="row"
              layout="list"
              @edit="handleEdit"
              @keys="openTokenDrawer"
              @manage-scopes="handleManageScopes"
              @open-password="openPassword"
              @open-identities="openIdentities"
              @changed="fetchUserList"
              @deleted="fetchUserList"
            />
          </template>
        </el-table-column>
        <template #empty>
          <EmptyState
            :title="$t('users.emptyTitle')"
            :hint="$t('users.emptyHint')"
          >
            <template #action>
              <el-button
                type="primary"
                size="small"
                @click="handleCreate"
              >
                <el-icon><Plus /></el-icon>
                {{ $t('users.create') }}
              </el-button>
            </template>
          </EmptyState>
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

    <UserAccountForm
      ref="accountFormRef"
      @saved="fetchUserList"
      @opening="closeOtherPanels"
      @issue-key="issueKeyForCreated"
    />

    <!-- 審核範圍對話框：
         approver-scope API 早已存在，本對話框補上缺線的管理 UI；
         admin only（後端 RequireRole 強制），資產 XOR 資產分組 -->
    <el-dialog
      v-model="scopeDialogVisible"
      :title="$t('users.scopeDialogTitle', { name: scopeUser.username })"
      width="560px"
      :close-on-click-modal="false"
    >
      <el-table
        v-loading="scopeLoading"
        :data="userScopes"
        stripe
        style="width: 100%"
      >
        <el-table-column
          :label="$t('users.scopeTypeColumn')"
          width="130"
        >
          <template #default="{ row }">
            <el-tag
              :type="scopeTypeTagType(row)"
              size="small"
            >
              {{ scopeTypeLabel(row) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('users.scopeTargetColumn')"
          min-width="180"
        >
          <template #default="{ row }">
            {{ scopeTargetLabel(row, scopeGroupPaths) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('users.assignedAt')"
          width="170"
        >
          <template #default="{ row }">
            {{ formatDateTime(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.actions')"
          width="80"
          fixed="right"
        >
          <template #default="{ row }">
            <el-button
              type="danger"
              size="small"
              link
              @click="handleRemoveScope(row)"
            >
              {{ $t('users.remove') }}
            </el-button>
          </template>
        </el-table-column>
        <template #empty>
          <EmptyState
            :title="$t('users.scopeEmptyTitle')"
            :hint="$t('users.scopeEmptyHint')"
          />
        </template>
      </el-table>

      <!-- 新增表單與矩陣頁共用（雙入口同組件防漂移） -->
      <ApproverScopeForm
        v-if="scopeDialogVisible && scopeUser.id"
        class="scope-add-form"
        :preset-actor="{ type: 'user', id: scopeUser.id }"
        @created="loadScopes"
      />
    </el-dialog>

    <UserAccountDialogs
      ref="accountDialogsRef"
      :refresh-user="refreshUser"
      @opening="closeOtherPanels"
    />
    <TokenDrawer
      v-model="tokenDrawerVisible"
      :principal="tokenPrincipal"
      :owner-name="tokenPrincipal.owner_username"
      @open="accountFormRef?.close()"
      @changed="fetchUserList"
    />
  </div>
</template>

<script setup>
import { expandRowA11y as vExpandRowA11y } from '@/directives/expandRowA11y'
import { ref, reactive, onMounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import {
  Plus,
  RefreshCw,
  Search,
  Lock,
  CircleCheck,
} from 'lucide-vue-next'
import { getUserList, getUserDetail, setInactivityExempt } from '@/api/user'
import PageHeader from '@/components/PageHeader.vue'
import PrincipalBadge from '@/components/agent/PrincipalBadge.vue'
import TokenDrawer from '@/components/agent/TokenDrawer.vue'
import EmptyState from '@/components/EmptyState.vue'
import UserAccountForm from './users/components/UserAccountForm.vue'
import UserAccountActions from './users/components/UserAccountActions.vue'
import UserAccountDialogs from './users/components/UserAccountDialogs.vue'
import { formatDateTime } from '@/utils/format'
import { apiErrorSummary } from '@/api/redact'
import { t } from '@/i18n'
import { roleLabel, roleTagType } from '@/constants/roles'
import { confirmDestructive } from '@/utils/confirm'
import { isLocked } from './users/accountActionStates'
import { handleStatusChange } from './users/accountActionHandlers'
import { effectiveUnrestrictedText } from './users/sourcePolicyText'
import ApproverScopeForm from '@/components/ApproverScopeForm.vue'
import {
  scopeTypeLabel,
  scopeTypeTagType,
  scopeTargetLabel,
  buildGroupPaths,
} from '@/utils/approver-scope'
import { getAssetGroups } from '@/api/assets'
import {
  getApproverScopes,
  deleteApproverScope,
} from '@/api/accessRequests'

// 元件層日誌一律走白名單摘要：本頁的請求本文含明文密碼
// 與 Email，把 AxiosError 原樣寫進 console 等同於在 DevTools 與集中日誌外洩
const logFailure = (event, error) => console.error(...apiErrorSummary(event, error))

// 資料狀態
const loading = ref(false)
const userList = ref([])
const pagination = reactive({
  page: 1,
  page_size: 20,
  total: 0,
})

// 過濾表單。類型與網址同步：側欄的「AI agent 主體」就是本頁 `?kind=agent`，
// 一個入口即到預篩過的清單，不必再拉一次下拉
// 元件測試不掛 router，useRoute()／useRouter() 會是 undefined：
// 網址同步是附加能力，缺了 router 仍要能純粹當列表用
const route = useRoute()
const router = useRouter()
const kindFromQuery = () => {
  const value = route?.query?.kind ?? new URLSearchParams(window.location.search).get('kind')
  return ['agent', 'human'].includes(value) ? value : ''
}
const filterForm = reactive({
  provisioningOrigin: '',
  kind: kindFromQuery(),
  search: '',
  active: '',
})

// 對話框狀態
const tokenDrawerVisible = ref(false)
const tokenPrincipal = ref({})
const accountFormRef = ref(null)
const accountDialogsRef = ref(null)

// —— 帳號來源與外部憑證判定——

// 供應來源值域（後端 model.AuthSource*）；未知值原樣顯示，不吞成「本地」
const KNOWN_AUTH_SOURCES = ['local', 'ldap', 'oidc']

// 供應來源標籤：以 provisioning_origin 為權威；舊後端無此欄時退回 is_ldap 推導
// 未知值不吞成「本地」，但也不直接輸出裸機器碼：後端日後加
// saml／oauth2 時，畫面應顯示「其他（saml）」而非違反 i18n 規範的裸值
const sourceLabel = (row) => {
  const origin = row?.provisioning_origin || (row?.is_ldap ? 'ldap' : 'local')
  return KNOWN_AUTH_SOURCES.includes(origin)
    ? t(`enum.authSource.${origin}`)
    : t('enum.authSource.unknown', { origin })
}

// 取得用戶列表。
// 回傳成功與否：呼叫端若把「刷新完成」當成「拿到新資料」，
// 失敗時會拿舊列表回填抽屜狀態，畫面上就出現「操作成功」後仍顯示舊狀態的假象
const fetchUserList = async () => {
  loading.value = true
  try {
    const params = {
      include_agents: true,
      kind: filterForm.kind || undefined,
      page: pagination.page,
      page_size: pagination.page_size,
      search: filterForm.search || undefined,
      active: filterForm.active !== '' ? filterForm.active : undefined,
      provisioning_origin: filterForm.provisioningOrigin || undefined,
    }

    const response = await getUserList(params)
    // 為每個用戶添加 loading 狀態標記
    userList.value = (response.data || []).map(user => ({
      ...user,
      _statusLoading: false,
      _exemptLoading: false,
    }))
    pagination.total = response.total || 0
    // 角色來源另讀（列表端點不帶 role_sets）。不擋列表顯示：
    // 讀不到只是少了來源標示，把整頁卡在這裡是拿次要資訊換主要資訊
    loadRoleSetsForRows(userList.value)
    return true
  } catch (error) {
    logFailure('user_list_failed', error)
    return false
  } finally {
    loading.value = false
  }
}

// 處理過濾
const handleFilter = () => {
  pagination.page = 1
  fetchUserList()
}

// 類型改由頁內下拉切換時把網址一併改掉，否則側欄仍亮在「AI agent 主體」
// 而清單已經不是 agent 了
const handleKindChange = () => {
  const next = filterForm.kind || undefined
  if (router && (route?.query?.kind || undefined) !== next) {
    const query = { ...route.query }
    if (next) query.kind = next
    else delete query.kind
    router.replace({ query })
  }
  handleFilter()
}

watch(() => route?.query?.kind, () => {
  const next = kindFromQuery()
  if (next === filterForm.kind) return
  filterForm.kind = next
  handleFilter()
})

// 重置過濾
const handleResetFilter = () => {
  if (router && route?.query?.kind) {
    const query = { ...route.query }
    delete query.kind
    router.replace({ query })
  }
  filterForm.kind = ''
  filterForm.search = ''
  filterForm.active = ''
  filterForm.provisioningOrigin = ''
  pagination.page = 1
  fetchUserList()
}

// 處理刷新
const handleRefresh = () => {
  fetchUserList()
}

// 處理分頁大小變更
const handleSizeChange = () => {
  fetchUserList()
}

// 處理頁碼變更
const handlePageChange = () => {
  fetchUserList()
}

// 切換閒置停用豁免：失敗回滾 switch，避免顯示與後端不一致
const handleExemptChange = async (row) => {
  row._exemptLoading = true
  try {
    await setInactivityExempt(row.id, row.inactivity_exempt)
    ElMessage.success(row.inactivity_exempt ? t('users.exemptSet') : t('users.exemptUnset'))
  } catch (error) {
    row.inactivity_exempt = !row.inactivity_exempt
  } finally {
    row._exemptLoading = false
  }
}

// 建立與編輯由帳號表單元件承載；這裡只負責開啟
const handleCreate = () => {
  tokenDrawerVisible.value = false
  accountFormRef.value?.openCreate()
}
const handleEdit = (row) => {
  tokenDrawerVisible.value = false
  accountFormRef.value?.openEdit(row)
}
const openPassword = (row) => accountDialogsRef.value?.openPassword(row)
const openIdentities = (row) => accountDialogsRef.value?.openIdentities(row)
const closeOtherPanels = () => { tokenDrawerVisible.value = false }

// 名稱與「分配角色」連到使用者詳情頁（角色與範圍在詳情頁的第二分頁）
const openDetail = (row, tab) => {
  router?.push(tab ? { path: `/users/${row.id}`, query: { tab } } : `/users/${row.id}`)
}

// 外部身分面板操作後的重新讀取：回是否讀到、以及該帳號的最新一列
const refreshUser = async (id) => {
  const ok = await fetchUserList()
  if (!ok) return { ok: false, user: null }
  return { ok: true, user: userList.value.find((u) => u.id === id) || null }
}

// —— 審核範圍管理（四維化，
// 新增表單收斂至共用 ApproverScopeForm，矩陣總覽在 /approver-scopes 獨立頁）——
const scopeDialogVisible = ref(false)
const scopeLoading = ref(false)
const scopeUser = reactive({ id: null, username: '' })
const userScopes = ref([])
const scopeGroupPaths = ref({})


const loadScopes = async () => {
  scopeLoading.value = true
  try {
    const res = await getApproverScopes()
    // 列表端點回全量（admin 視圖），對話框僅取目前使用者
    userScopes.value = (res.data || []).filter((sc) => sc.approver_id === scopeUser.id)
  } catch (error) {
    logFailure('approver_scope_list_failed', error)
  } finally {
    scopeLoading.value = false
  }
}

// 節點全路徑（同名節點可分辨；表格顯示用，惰性載一次）
const loadScopeGroupPaths = async () => {
  if (Object.keys(scopeGroupPaths.value).length) return
  try {
    const res = await getAssetGroups()
    scopeGroupPaths.value = buildGroupPaths(res.data || [])
  } catch (error) {
    logFailure('asset_group_list_failed', error)
  }
}

const handleManageScopes = (row) => {
  scopeUser.id = row.id
  scopeUser.username = row.username
  scopeDialogVisible.value = true
  loadScopes()
  loadScopeGroupPaths()
}

const handleRemoveScope = async (row) => {
  const target = scopeTargetLabel(row, scopeGroupPaths.value)
  try {
    await confirmDestructive(
      t('users.removeScopeConfirm', { name: scopeUser.username, target }),
      t('users.removeScopeTitle'),
      {
        confirmButtonText: t('users.remove'),
        cancelButtonText: t('common.cancel'),
      }
    )
  } catch {
    return
  }
  try {
    await deleteApproverScope(row.id)
    ElMessage.success(t('users.scopeRemoved'))
    await loadScopes()
  } catch (error) {
    logFailure('approver_scope_remove_failed', error)
  }
}

// —— 角色來源（管理者指派集／外部群組映射集）——
//
// 有效角色集（`row.roles`）分不出一個角色是誰給的，而撤走它的方法依來源不同。
// 兩份集合的事實源是 `GET /users/:id` 的 `role_sets`，列表端點不帶這個欄位。
//
// **不逐列去讀**：每一次讀取都是一列稽核記錄，一頁 20 列就是 20 列「讀取使用者」，
// 每次刷新再來一輪。故只在**可能**有映射成分的列上讀：映射角色與群組觀測快照
// 在同一個交易裡寫入，沒有快照時間的帳號從未有過一次成功的群組觀測，
// 也就不可能有映射賦予的角色——那些列的角色全部是管理者指派，零請求即可斷定。
const roleSetsById = reactive({})
const roleSetsUnknownIds = reactive(new Set())
let roleSetsSeq = 0

const couldHaveMappedRoles = (row) => Boolean(row?.group_snapshot_at)

const loadRoleSetsForRows = async (rows) => {
  const seq = ++roleSetsSeq
  const targets = rows.filter(couldHaveMappedRoles)
  roleSetsUnknownIds.clear()
  // 併發上限：管理面的列表刷新不該一次打出整頁的請求
  const queue = [...targets]
  const worker = async () => {
    while (queue.length) {
      const row = queue.shift()
      try {
        const res = await getUserDetail(row.id)
        if (seq !== roleSetsSeq) return
        if (res?.role_sets) {
          roleSetsById[row.id] = res.role_sets
        } else {
          roleSetsUnknownIds.add(row.id)
        }
      } catch (error) {
        if (seq !== roleSetsSeq) return
        // 讀不到就不標來源。猜一個是把「不知道」呈現成「管理者指派」，
        // 而那正是這一欄要防的誤讀
        roleSetsUnknownIds.add(row.id)
        logFailure('user_role_sets_failed', error)
      }
    }
  }
  await Promise.all([worker(), worker(), worker()])
}

// 一個角色在該帳號上的來源：manual／mapped／both；不確定時回空字串（不標示）
const roleSourceOf = (row, name) => {
  const sets = roleSetsById[row.id]
  if (sets) {
    const manual = (sets.manual || []).includes(name)
    const mapped = (sets.mapped || []).includes(name)
    if (manual && mapped) return 'both'
    if (mapped) return 'mapped'
    if (manual) return 'manual'
    return ''
  }
  if (roleSetsUnknownIds.has(row.id)) return ''
  return couldHaveMappedRoles(row) ? '' : 'manual'
}

// 映射賦予審核者角色的帳號：映射只給角色，不會連帶產生審核範圍
const needsApproverScope = (row) => {
  const sets = roleSetsById[row.id]
  return Boolean(sets && (sets.mapped || []).includes('approver'))
}

// 掛載時取得資料
function openTokenDrawer(row) {
  accountFormRef.value?.close()
  accountDialogsRef.value?.close()
  scopeDialogVisible.value = false
  tokenPrincipal.value = row
  tokenDrawerVisible.value = true
}
// 「現在發鑰匙」：關掉對話框、直接打開這個 agent 的鑰匙抽屜。
// 列表刷新回來就用列表那一列（欄位最完整），還沒回來就用建立回應
function issueKeyForCreated(agent) {
  if (!agent) return
  const row = userList.value.find(user => user.id === agent.id)
  openTokenDrawer(row ? { ...row, owner_username: row.owner_username || agent.owner_username } : agent)
}
// `/users?open=<id>`：任務詳情與熔斷頁可直達該 agent 的鑰匙抽屜，
// 不必回側欄捲到「使用者管理」再自己找人
async function openFromQuery() {
  const id = Number(new URLSearchParams(window.location.search).get('open'))
  if (!Number.isInteger(id) || id <= 0) return
  const row = userList.value.find(user => user.id === id)
  if (row) { openTokenDrawer(row); return }
  try {
    const response = await getUserDetail(id)
    const user = response?.data || response
    if (user?.id) openTokenDrawer(user)
  } catch { /* 讀不到就停在列表；錯誤訊息由攔截器呈現 */ }
}
onMounted(async () => {
  await fetchUserList()
  openFromQuery()
})
</script>

<style scoped>
/* provider 實例名緊接在來源標籤後；換行時不擠壓表格其他欄 */
.source-provider-tag {
  margin-left: 4px;
}

/* 角色與其來源標示成對出現，換行時一起換 */
.role-cell {
  display: inline-flex;
  align-items: center;
  white-space: nowrap;
}

.role-source-tag {
  margin-left: 4px;
}

/* 儲存格第二行：次要事實，不與第一行爭視覺權重 */
.cell-subline {
  margin-top: 4px;
  font-size: var(--ot-font-size-xs);
  line-height: 1.4;
  color: var(--ot-text-secondary);
}

.dialog-hint {
  margin-bottom: 8px;
  font-size: var(--ot-font-size-xs);
  line-height: 1.5;
  color: var(--ot-text-secondary);
}

.dialog-hint--warning {
  color: var(--ot-warning);
}

.mapped-roles-block {
  margin-top: 4px;
  padding-top: 12px;
  border-top: 1px solid var(--el-border-color-lighter);
}

.mapped-roles-block__title {
  margin-bottom: 8px;
  font-size: var(--ot-font-size-md);
  font-weight: 500;
}

.mapped-roles-block__alert {
  margin-top: 8px;
}

.mapped-role-row {
  margin-bottom: 4px;
}

.mapped-role-row__note {
  margin-left: 6px;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.group-snapshot-block {
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px solid var(--el-border-color-lighter);
}

.group-snapshot-block__title {
  margin-bottom: 8px;
  font-size: var(--ot-font-size-md);
  font-weight: 500;
}

.group-snapshot-block__meta {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.group-snapshot-block__list {
  margin: 8px 0 0;
  padding-left: 18px;
}

.group-snapshot-block__list li {
  font-family: var(--ot-font-mono, monospace);
  font-size: var(--ot-font-size-xs);
  word-break: break-all;
}

.users {
  /* MainLayout main-content 已有 padding，此處不重複加 */
}

/* 主欄的帳號名與副行（全名）：省下一整欄，且兩者本就該同讀 */
.cell-main {
  font-weight: 500;
}

.user-link {
  color: var(--ot-text-primary);
  text-decoration: none;
}

.user-link:hover {
  color: var(--ot-primary);
  text-decoration: underline;
}

.cell-sub {
  margin-top: 2px;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  word-break: break-all;
}

/* 展開列：次要欄位與閒置豁免開關的落腳處 */
.row-detail {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: var(--ot-space-xs) var(--ot-space-md);
  padding: var(--ot-space-xs) var(--ot-space-md);
}

.row-detail__item {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  min-height: 28px;
}

.row-detail__label {
  flex: none;
  min-width: 84px;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

.row-detail__value {
  word-break: break-all;
}

.drawer-alert {
  margin-bottom: var(--ot-space-md);
}

/* 帶說明的欄位標頭：虛線下標示可 hover 取得 tooltip（沿用 Element Plus 深色主題色票） */
.col-header-hint {
  border-bottom: 1px dashed var(--ot-border-subtle);
  cursor: help;
}

.filter-bar {
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  margin-bottom: var(--ot-space-md);
}

.list-card {
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  min-height: 400px;
}

.pagination {
  margin-top: var(--ot-space-md);
  display: flex;
  justify-content: flex-end;
}
</style>
