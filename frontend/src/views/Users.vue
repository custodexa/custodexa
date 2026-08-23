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
          <el-icon><Refresh /></el-icon>
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
            <el-icon><Refresh /></el-icon>
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
              <div class="row-detail__item">
                <span class="row-detail__label">{{ $t('users.lastLogin') }}</span>
                <span class="row-detail__value">
                  {{ row.last_login_at ? formatDateTime(row.last_login_at) : $t('users.neverLoggedIn') }}
                </span>
              </div>
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
        <el-table-column
          prop="id"
          label="ID"
          width="70"
          sortable
        />
        <el-table-column
          prop="username"
          :label="$t('common.username')"
          min-width="180"
        >
          <template #default="{ row }">
            <div class="cell-main">
              {{ row.username }}
            </div>
            <!-- 全名以副行呈現：省下一整欄，且「這是誰」本來就該與帳號同讀 -->
            <div
              v-if="row.full_name"
              class="cell-sub"
            >
              {{ row.full_name }}
            </div>
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
        <el-table-column
          :label="$t('common.role')"
          min-width="130"
        >
          <template #default="{ row }">
            <el-space wrap>
              <el-tag
                v-for="role in (row.roles || [])"
                :key="role.id || role.name || role"
                :type="roleTagType(role.name || role)"
                size="small"
              >
                {{ roleLabel(role.name || role) }}
              </el-tag>
              <el-tag
                v-if="!row.roles || row.roles.length === 0"
                type="info"
                size="small"
              >
                {{ $t('users.noRole') }}
              </el-tag>
            </el-space>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.status')"
          width="112"
        >
          <template #default="{ row }">
            <el-space :size="6">
              <el-switch
                v-model="row.active"
                :loading="row._statusLoading"
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
            </el-space>
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
            <!-- 三顆按鈕不帶圖示：圖示在 en 下把本欄推到 280+，直接吃掉表格預算，
                 而「編輯／外部身分」在文字之外沒有額外辨識價值 -->
            <el-button
              type="primary"
              size="small"
              link
              @click="handleEdit(row)"
            >
              {{ $t('common.edit') }}
            </el-button>
            <!-- 外部身分管理：對每個帳號都開放——
                 本地帳號亦可由 admin 綁定外部身分（UA-1「admin SHALL 可為既有帳號
                 顯式綁定」），只對 oidc 來源開放會使該路徑無從進入。
                 這是本 change 的主要入口，維持常駐可見，不收進選單 -->
            <el-button
              type="primary"
              size="small"
              link
              @click="handleManageIdentities(row)"
            >
              {{ $t('users.externalIdentities') }}
            </el-button>
            <el-dropdown
              class="row-more"
              trigger="click"
              placement="bottom-end"
              :popper-options="menuPopperOptions"
              @command="(cmd) => handleRowCommand(cmd, row)"
            >
              <el-button
                size="small"
                link
              >
                {{ $t('common.more') }}<el-icon class="more-caret">
                  <ArrowDown />
                </el-icon>
              </el-button>
              <template #dropdown>
                <el-dropdown-menu>
                  <!-- 變更密碼：外部身分帳號無本地密碼，保留項目但停用並
                       就地說明原因（隱藏會讓人以為功能不存在）。停用項的 tooltip
                       在 EP 下不會觸發（pointer-events: none），故原因寫成副行；
                       用短句而非完整 tooltip 文案——長句會把選單撐到 217×297，
                       在最後幾列會同時貼齊視窗右緣與下緣 -->
                  <el-dropdown-item
                    command="changePassword"
                    :disabled="isExternalAccount(row)"
                  >
                    <!-- 包一層自有容器：`el-dropdown-item` 的根元素**不帶本元件的
                         scoped 屬性**（EP 內部以 collection item 重新渲染），
                         直接對它下 scoped 樣式不會生效；而該根是 flex row，
                         副行不包起來會被排到標題右側，把選單撐到 336px 寬 -->
                    <div class="item-body">
                      <span>{{ $t('common.changePassword') }}</span>
                      <span
                        v-if="isExternalAccount(row)"
                        class="item-note"
                      >{{ $t('users.externalPasswordShort') }}</span>
                    </div>
                  </el-dropdown-item>
                  <el-dropdown-item command="assignRoles">
                    {{ $t('users.assignRoles') }}
                  </el-dropdown-item>
                  <el-dropdown-item
                    v-if="hasApproverRole(row)"
                    command="scopes"
                  >
                    {{ $t('menu.approverScopes') }}
                  </el-dropdown-item>
                  <el-dropdown-item
                    v-if="isLocked(row)"
                    command="unlock"
                  >
                    {{ $t('users.unlock') }}
                  </el-dropdown-item>
                  <el-dropdown-item
                    v-if="row.totp_enabled"
                    command="disableMfa"
                    divided
                  >
                    <span class="danger-item">{{ $t('common.disableMfa') }}</span>
                  </el-dropdown-item>
                  <el-dropdown-item
                    command="delete"
                    divided
                  >
                    <span class="danger-item">{{ $t('common.delete') }}</span>
                  </el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
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

    <!-- 創建/編輯用戶對話框 -->
    <el-dialog
      v-model="dialogVisible"
      :title="dialogTitle"
      width="560px"
      :close-on-click-modal="false"
    >
      <el-form
        ref="formRef"
        :model="form"
        :rules="formRules"
        label-position="top"
      >
        <el-form-item
          :label="$t('common.username')"
          prop="username"
        >
          <el-input
            v-model="form.username"
            :placeholder="$t('users.usernamePlaceholder')"
            :disabled="isEdit"
          />
        </el-form-item>
        <el-form-item
          v-if="!isEdit"
          :label="$t('common.password')"
          prop="password"
        >
          <el-input
            v-model="form.password"
            type="password"
            :placeholder="$t('users.passwordPlaceholder')"
            show-password
          />
        </el-form-item>
        <el-form-item
          label="Email"
          prop="email"
        >
          <el-input
            v-model="form.email"
            :placeholder="$t('users.emailPlaceholder')"
          />
        </el-form-item>
        <el-form-item
          :label="$t('users.fullName')"
          prop="full_name"
        >
          <el-input
            v-model="form.full_name"
            :placeholder="$t('users.fullNamePlaceholder')"
          />
        </el-form-item>
        <el-form-item
          v-if="!isEdit"
          :label="$t('common.role')"
          prop="roles"
        >
          <!-- 由 /roles API 生成（補遺）：勿硬編碼 -->
          <el-checkbox-group v-model="form.roles">
            <el-checkbox
              v-for="role in assignableRoles"
              :key="role.name"
              :label="role.name"
            >
              {{ roleLabel(role.name) }}
            </el-checkbox>
          </el-checkbox-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="submitting"
          @click="handleSubmit"
        >
          {{ $t('common.confirm') }}
        </el-button>
      </template>
    </el-dialog>

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

    <!-- 分配角色對話框 -->
    <el-dialog
      v-model="roleDialogVisible"
      :title="$t('users.assignRoles')"
      width="480px"
      :close-on-click-modal="false"
    >
      <el-alert
        :title="$t('users.currentUser')"
        :description="$t('users.currentUserDesc', { name: currentUser.username })"
        type="info"
        :closable="false"
        style="margin-bottom: 20px"
      />
      <!-- 可指派清單由 /roles API 拉取：
           後端新增角色自動出現，勿硬編碼 checkbox -->
      <el-form label-position="top">
        <el-form-item :label="$t('common.role')">
          <el-checkbox-group v-model="selectedRoles">
            <el-checkbox
              v-for="role in assignableRoles"
              :key="role.name"
              :label="role.name"
            >
              {{ roleLabel(role.name) }}
            </el-checkbox>
          </el-checkbox-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="roleDialogVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="submitting"
          @click="handleRoleSubmit"
        >
          {{ $t('common.confirm') }}
        </el-button>
      </template>
    </el-dialog>

    <!-- 修改密碼對話框 -->
    <el-dialog
      v-model="passwordDialogVisible"
      :title="$t('common.changePassword')"
      width="480px"
      :close-on-click-modal="false"
    >
      <el-alert
        :title="$t('users.currentUser')"
        :description="$t('users.currentUserDesc', { name: currentUser.username })"
        type="info"
        :closable="false"
        style="margin-bottom: 20px"
      />
      <el-form
        ref="passwordFormRef"
        :model="passwordForm"
        :rules="passwordRules"
        label-position="top"
      >
        <el-form-item
          :label="$t('common.newPassword')"
          prop="password"
        >
          <el-input
            v-model="passwordForm.password"
            type="password"
            :placeholder="$t('users.newPasswordPlaceholder')"
            show-password
          />
        </el-form-item>
        <el-form-item
          :label="$t('users.confirmPassword')"
          prop="confirmPassword"
        >
          <el-input
            v-model="passwordForm.confirmPassword"
            type="password"
            :placeholder="$t('users.confirmPasswordPlaceholder')"
            show-password
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="passwordDialogVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="submitting"
          @click="handlePasswordSubmit"
        >
          {{ $t('common.confirm') }}
        </el-button>
      </template>
    </el-dialog>

    <!-- 外部身分管理。
         承載形式定案為**抽屜**而非獨立路由頁：內容是既有列表列的縱深（基本資料
         已在列上），抽屜可保留列表脈絡且不需新增路由與側欄項目；表格本體抽成
         獨立元件，抽屜只是殼（happy-dom 對 el-drawer 的 teleport 不友善，
         元件單測直接測本體） -->
    <el-drawer
      v-model="identityDrawerVisible"
      :title="$t('externalIdentities.drawerTitle', { name: identityUser.username })"
      size="90%"
      direction="rtl"
    >
      <!-- 面板操作成功但列表刷新失敗：抽屜標頭與帳號狀態
           標籤仍是舊值，不得靜默——尤其「可轉換為僅外部登入」這種以舊狀態為前提
           的入口，會讓管理者對已轉換的帳號再按一次 -->
      <el-alert
        v-if="identityRefreshFailed"
        class="drawer-alert"
        type="warning"
        :title="$t('users.identityRefreshFailedTitle')"
        :description="$t('users.identityRefreshFailedHint')"
        :closable="false"
        show-icon
      >
        <template #default>
          <div>{{ $t('users.identityRefreshFailedHint') }}</div>
          <!-- 顯式帶 user id：handler 以 id 判定事件歸屬，直接綁事件會把
               MouseEvent 當成目標 id 傳進去 -->
          <el-button
            size="small"
            :loading="loading"
            @click="handleIdentitiesChanged(identityUser.id)"
          >
            {{ $t('common.retry') }}
          </el-button>
        </template>
      </el-alert>
      <!-- :key 綁 user id：換使用者時強制重建元件，
           連同在途請求與表單狀態一併丟棄，不倚賴元件內部的清理是否完備 -->
      <UserExternalIdentities
        v-if="identityDrawerVisible && identityUser.id"
        :key="identityUser.id"
        :user="identityUser"
        :account-state-stale="identityRefreshFailed"
        @changed="handleIdentitiesChanged"
      />
    </el-drawer>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import {
  Plus,
  Refresh,
  Search,
  Lock,
  CircleCheck,
  ArrowDown,
} from '@element-plus/icons-vue'
import {
  getRoleList,
  getUserList,
  createUser,
  updateUser,
  deleteUser,
  assignRoles,
  updateUserStatus,
  changePassword,
  adminDisableMFA,
  unlockUser,
  setInactivityExempt,
} from '@/api/user'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import { formatDateTime } from '@/utils/format'
import { confirmDestructive } from '@/utils/confirm'
import { apiErrorSummary } from '@/api/redact'
import { t } from '@/i18n'
import { roleLabel, roleTagType } from '@/constants/roles'
import { hasRole } from '@/composables/useRoles'
import ApproverScopeForm from '@/components/ApproverScopeForm.vue'
import UserExternalIdentities from '@/components/UserExternalIdentities.vue'
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

// 過濾表單
const filterForm = reactive({
  provisioningOrigin: '',
  search: '',
  active: '',
})

// 對話框狀態
const dialogVisible = ref(false)
const roleDialogVisible = ref(false)
const passwordDialogVisible = ref(false)
const isEdit = ref(false)
const submitting = ref(false)
const formRef = ref(null)
const passwordFormRef = ref(null)

// 表單資料
const form = reactive({
  id: null,
  username: '',
  password: '',
  email: '',
  full_name: '',
  roles: [],
})

// 目前選中的用戶
const currentUser = reactive({
  id: null,
  username: '',
})

// 選中的角色
const selectedRoles = ref([])

// 密碼表單
const passwordForm = reactive({
  password: '',
  confirmPassword: '',
})

// 對話框標題
const dialogTitle = computed(() => {
  return isEdit.value ? t('users.editTitle') : t('users.create')
})

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

// 憑證是否由外部提供者管理：external_credential 為權威旗標；
// 舊後端無此欄時退回 is_ldap（LDAP 影子帳號同樣無本地密碼）
const isExternalAccount = (row) =>
  row?.external_credential === true ||
  (row?.external_credential === undefined && row?.is_ldap === true)

// 列上「更多」選單靠右對齊（bottom-end）：en-US 的長項目會把選單推到距視窗
// 右緣僅 1px。preventOverflow 的 padding 保底留白，
// 與抽屜內選單的視覺留白一致。保留 EP 預設的 computeStyles 設定
const menuPopperOptions = {
  modifiers: [
    { name: 'computeStyles', options: { gpuAcceleration: false } },
    { name: 'preventOverflow', options: { padding: 12 } },
  ],
}

// 表單驗證規則（computed：切語言時錯誤訊息隨當下語言）
const formRules = computed(() => ({
  username: [
    { required: true, message: t('users.usernamePlaceholder'), trigger: 'blur' },
    { min: 3, max: 50, message: t('users.usernameLength'), trigger: 'blur' },
  ],
  password: [
    { required: true, message: t('users.passwordPlaceholder'), trigger: 'blur' },
  ],
  email: [
    { required: true, message: t('users.emailPlaceholder'), trigger: 'blur' },
    { type: 'email', message: t('users.emailInvalid'), trigger: 'blur' },
  ],
}))

// 密碼驗證規則
const validateConfirmPassword = (rule, value, callback) => {
  if (value !== passwordForm.password) {
    callback(new Error(t('users.passwordMismatch')))
  } else {
    callback()
  }
}

const passwordRules = computed(() => ({
  password: [
    { required: true, message: t('users.newPasswordRequired'), trigger: 'blur' },
  ],
  confirmPassword: [
    { required: true, message: t('users.confirmPasswordRequired'), trigger: 'blur' },
    { validator: validateConfirmPassword, trigger: 'blur' },
  ],
}))

// 取得用戶列表。
// 回傳成功與否：呼叫端若把「刷新完成」當成「拿到新資料」，
// 失敗時會拿舊列表回填抽屜狀態，畫面上就出現「操作成功」後仍顯示舊狀態的假象
const fetchUserList = async () => {
  loading.value = true
  try {
    const params = {
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

// 重置過濾
const handleResetFilter = () => {
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

// 處理狀態變更
const handleStatusChange = async (row) => {
  row._statusLoading = true
  try {
    await updateUserStatus(row.id, row.active)
    ElMessage.success(t('users.statusUpdated'))
  } catch (error) {
    // 恢復原狀態
    row.active = !row.active
  } finally {
    row._statusLoading = false
  }
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

// 重置表單
const resetForm = () => {
  form.id = null
  form.username = ''
  form.password = ''
  form.email = ''
  form.full_name = ''
  form.roles = []
  formRef.value?.clearValidate()
}

// 處理創建
const handleCreate = () => {
  loadAssignableRoles()
  resetForm()
  isEdit.value = false
  dialogVisible.value = true
}

// 處理編輯
const handleEdit = (row) => {
  resetForm()
  isEdit.value = true
  form.id = row.id
  form.username = row.username
  form.email = row.email || ''
  form.full_name = row.full_name || ''
  dialogVisible.value = true
}

// 處理提交
const handleSubmit = async () => {
  try {
    await formRef.value.validate()
    submitting.value = true

    if (isEdit.value) {
      // 更新用戶
      const data = {
        email: form.email,
        full_name: form.full_name,
      }
      await updateUser(form.id, data)
      ElMessage.success(t('users.updated'))
    } else {
      // 新增使用者
      const data = {
        username: form.username,
        password: form.password,
        email: form.email,
        full_name: form.full_name,
        roles: form.roles.length > 0 ? form.roles : ['user'],
      }
      await createUser(data)
      ElMessage.success(t('users.created'))
    }

    dialogVisible.value = false
    fetchUserList()
  } catch (error) {
    if (error?.errors) {
      // 驗證錯誤，不需要處理
      return
    }
    logFailure('user_submit_failed', error)
  } finally {
    submitting.value = false
  }
}

// —— 審核範圍管理（四維化，
// 新增表單收斂至共用 ApproverScopeForm，矩陣總覽在 /approver-scopes 獨立頁）——
const scopeDialogVisible = ref(false)
const scopeLoading = ref(false)
const scopeUser = reactive({ id: null, username: '' })
const userScopes = ref([])
const scopeGroupPaths = ref({})

// 物件/字串兩形判定收斂至 useRoles 的 hasRole，本頁不再自寫
const hasApproverRole = (row) => hasRole(row.roles, 'approver')

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

// —— 外部身分管理——
// 傳整列（而非只有 id）：面板需要 username 與 external_credential 才能把
// 「解綁後這個帳號還能不能登入」講清楚
const identityDrawerVisible = ref(false)
const identityUser = ref({ id: null, username: '' })
// 列表刷新失敗＝抽屜顯示的帳號狀態不可信；面板據此停掉不可逆的轉換入口
const identityRefreshFailed = ref(false)

const handleManageIdentities = (row) => {
  identityUser.value = { ...row }
  identityRefreshFailed.value = false
  identityDrawerVisible.value = true
}

// 面板內的破壞性操作（解綁＋停用、改為僅外部登入）會改變帳號本體狀態。
// 只刷新列表而不回填抽屜標頭，管理者會看到「操作成功」的 toast 消失後畫面
// 仍寫著舊狀態，無從自證剛才那一下是否生效。
//
// 刷新本身也會失敗：`fetchUserList` 吞掉錯誤並保留舊列表，
// 舊版把它當成一定成功，於是 external-only 轉換成功後畫面仍顯示「具本地密碼、
// 可轉換」——管理者會再按一次，或據此判斷轉換沒生效。失敗時一律標記狀態過期，
// 由抽屜警示與面板的入口停用共同承擔，不靜默
//
// 事件歸屬與順序：面板可在換人／卸載後才收到成功回應，
// 該事件帶的是**當時**的 user id；與目前抽屜不符時一律忽略，否則等於拿別人的
// 操作驅動這個帳號的狀態。同時以序號防止較舊的刷新覆蓋較新的結論
let identityRefreshSeq = 0

const handleIdentitiesChanged = async (userId) => {
  const targetId = identityUser.value?.id ?? null
  if (userId != null && userId !== targetId) return
  const seq = ++identityRefreshSeq
  const refreshed = await fetchUserList()
  // 期間又發生新的刷新或換了使用者：本次結論一律作廢
  if (seq !== identityRefreshSeq || identityUser.value?.id !== targetId) return
  if (!refreshed) {
    identityRefreshFailed.value = true
    return
  }
  const fresh = userList.value.find((u) => u.id === targetId)
  if (!fresh) {
    // 刷新成功但目標缺席（篩選、分頁，或操作本身讓帳號退出目前結果集）：
    // 抽屜上的帳號狀態同樣是舊值，清掉旗標等於重新開放不可逆入口
    identityRefreshFailed.value = true
    return
  }
  identityUser.value = { ...fresh }
  identityRefreshFailed.value = false
}

// 可指派角色清單：/roles API 為事實源（開窗時惰性載入一次，失敗下次開窗重試）
const assignableRoles = ref([])
const loadAssignableRoles = async () => {
  if (assignableRoles.value.length) return
  try {
    const res = await getRoleList()
    assignableRoles.value = res.data || []
  } catch (error) {
    logFailure('role_list_failed', error)
  }
}

// 處理分配角色
const handleAssignRoles = (row) => {
  currentUser.id = row.id
  currentUser.username = row.username
  // 提取角色名稱（處理物件陣列和字串陣列兩種情況）
  selectedRoles.value = (row.roles || []).map(role =>
    typeof role === 'object' ? role.name : role
  )
  loadAssignableRoles()
  roleDialogVisible.value = true
}

// 處理角色提交
const handleRoleSubmit = async () => {
  submitting.value = true
  try {
    await assignRoles(currentUser.id, selectedRoles.value)
    ElMessage.success(t('users.rolesAssigned'))
    roleDialogVisible.value = false
    fetchUserList()
  } catch (error) {
    logFailure('user_role_assign_failed', error)
  } finally {
    submitting.value = false
  }
}

// 處理修改密碼
const handleChangePassword = (row) => {
  currentUser.id = row.id
  currentUser.username = row.username
  passwordForm.password = ''
  passwordForm.confirmPassword = ''
  passwordFormRef.value?.clearValidate()
  passwordDialogVisible.value = true
}

// 處理密碼提交
const handlePasswordSubmit = async () => {
  try {
    await passwordFormRef.value.validate()
    submitting.value = true

    await changePassword(currentUser.id, passwordForm.password)
    ElMessage.success(t('users.passwordChanged'))
    passwordDialogVisible.value = false
  } catch (error) {
    if (error?.errors) {
      // 驗證錯誤，不需要處理
      return
    }
  } finally {
    submitting.value = false
  }
}

// 管理員停用用戶 MFA
// 鎖定狀態（8.3.4）：locked_until 未到才算鎖定中（到期由後端登入時自動放行）
const isLocked = (row) =>
  row.locked_until && new Date(row.locked_until) > new Date()

// 管理員手動解鎖：清除失敗計數與鎖定時間（後端入審計）
const handleUnlock = async (row) => {
  try {
    await unlockUser(row.id)
    ElMessage.success(t('users.unlocked', { name: row.username }))
    fetchUserList()
  } catch (error) {
    logFailure('user_unlock_failed', error)
  }
}

const handleAdminDisableMFA = async (row) => {
  try {
    await confirmDestructive(
      t('users.disableMFAConfirm', { name: row.username }),
      t('users.disableMFATitle'),
      {
        confirmButtonText: t('common.confirm'),
        cancelButtonText: t('common.cancel'),
      }
    )
  } catch {
    return // 使用者取消
  }

  try {
    await adminDisableMFA(row.id)
    ElMessage.success(t('users.mfaDisabled'))
    fetchUserList()
  } catch (error) {
    logFailure('user_mfa_disable_failed', error)
  }
}

// 處理刪除
const handleDelete = async (row) => {
  try {
    await confirmDestructive(
      t('users.deleteConfirm', { name: row.username }),
      t('common.deleteConfirmTitle'),
      {
        confirmButtonText: t('common.deleteConfirmButton'),
        cancelButtonText: t('common.cancel'),
      }
    )
  } catch {
    return // 使用者取消
  }

  try {
    await deleteUser(row.id)
    ElMessage.success(t('users.deleted'))
    fetchUserList()
  } catch (error) {
    logFailure('user_delete_failed', error)
  }
}

// 「更多」選單的命令分派：選單項不各自綁 handler，集中一處才看得出哪些操作
// 被收進選單（以及哪些是破壞性的）
const handleRowCommand = (command, row) => {
  const handlers = {
    changePassword: handleChangePassword,
    assignRoles: handleAssignRoles,
    scopes: handleManageScopes,
    unlock: handleUnlock,
    disableMfa: handleAdminDisableMFA,
    delete: handleDelete,
  }
  handlers[command]?.(row)
}

// 掛載時取得資料
onMounted(() => {
  fetchUserList()
})
</script>

<style scoped>
/* provider 實例名緊接在來源標籤後；換行時不擠壓表格其他欄 */
.source-provider-tag {
  margin-left: 4px;
}

.users {
  /* MainLayout main-content 已有 padding，此處不重複加 */
}

.more-caret {
  margin-left: 2px;
}

/* Element Plus 的按鈕間距靠相鄰選擇器 `.el-button + .el-button` 給，被
   `el-dropdown` 包住的按鈕不再是前一顆的相鄰兄弟，margin 直接失效——
   結果是「更多」觸發鈕與前一顆按鈕的點擊熱區貼在一起（gap 0px），
   且 el-dropdown 預設 vertical-align: top 使兩者基線差 4px */
.row-more {
  margin-left: 12px;
  vertical-align: middle;
}

/* 選單內的破壞性項目與一般項目分色（配合 divided 分隔線） */
.danger-item {
  color: var(--el-color-danger);
}

/* 停用選單項的原因就地說明（停用項不觸發 tooltip） */
.item-body {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  line-height: 1.4;
}

.item-note {
  display: block;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.4;
}

/* 主欄的帳號名與副行（全名）：省下一整欄，且兩者本就該同讀 */
.cell-main {
  font-weight: 500;
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
