<template>
  <div class="assets">
    <!-- 分角色文案：一般 user 的職能是連線不是管理 -->
    <PageHeader
      :title="isAdminOrAuditor ? $t('menu.assets') : $t('menu.myAssets')"
      :description="isAdminOrAuditor ? $t('assets.headerDescAdmin') : $t('assets.headerDescUser')"
    >
      <template #actions>
        <el-button @click="fetchAssetList">
          <el-icon><RefreshCw /></el-icon>
          {{ $t('common.refresh') }}
        </el-button>
        <!-- 標籤治理單獨入口：全面改名/合併/刪除 -->
        <el-button
          v-if="isAdmin"
          @click="tagManagerVisible = true"
        >
          <el-icon><Tag /></el-icon>
          {{ $t('assets.tagManager') }}
        </el-button>
        <el-button
          v-if="isAdmin"
          type="primary"
          @click="handleCreate"
        >
          <el-icon><Plus /></el-icon>
          {{ $t('assets.create') }}
        </el-button>
      </template>
    </PageHeader>

    <!-- 搜尋與過濾 -->
    <div class="filter-bar">
      <el-form
        :inline="true"
        :model="filterForm"
      >
        <el-form-item :label="$t('common.search')">
          <el-input
            v-model="filterForm.search"
            :placeholder="$t('assets.searchPlaceholder')"
            clearable
            @clear="handleFilter"
            @keyup.enter="handleFilter"
          >
            <template #prefix>
              <el-icon><Search /></el-icon>
            </template>
          </el-input>
        </el-form-item>
        <el-form-item :label="$t('common.protocol')">
          <el-select
            v-model="filterForm.protocol"
            :placeholder="$t('common.all')"
            clearable
            style="width: 120px"
            @change="handleFilter"
          >
            <el-option
              label="SSH"
              value="ssh"
            />
            <el-option
              label="RDP"
              value="rdp"
            />
            <el-option
              label="VNC"
              value="vnc"
            />
            <el-option
              label="MySQL"
              value="mysql"
            />
            <el-option
              label="PostgreSQL"
              value="postgres"
            />
            <el-option
              label="Redis"
              value="redis"
            />
            <el-option
              label="SQL Server"
              value="mssql"
            />
            <el-option
              label="K8s"
              value="k8s"
            />
          </el-select>
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
        <!-- 標籤篩選：僅 admin/auditor——
             一般 user 走授權分支不支援 tags 參數（伺服端 400） -->
        <el-form-item
          v-if="isAdminOrAuditor"
          :label="$t('common.tags')"
        >
          <el-select
            v-model="filterForm.tags"
            multiple
            filterable
            collapse-tags
            clearable
            :placeholder="$t('common.all')"
            class="tag-filter-select"
            :filter-method="filterTagMethod"
            @change="handleFilter"
            @visible-change="resetFilterTagOptions"
          >
            <el-option
              v-for="name in visibleFilterTags"
              :key="name"
              :label="name"
              :value="name"
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
        <!-- 欄位自訂齒輪：池欄找回的路 -->
        <el-form-item class="column-settings-item">
          <AssetColumnSettings
            v-model="optionalColumns"
            :pool="columnPool"
            @reset="resetColumnPrefs"
          />
        </el-form-item>
      </el-form>
    </div>

    <!-- 左樹右表：樹＝瀏覽＋授權分配主軸 -->
    <div class="tree-table-layout">
      <AssetNodeTree
        ref="nodeTreeRef"
        :is-admin="isAdmin"
        @select="handleNodeSelect"
        @authorize="handleAuthorizeNode"
      />

      <!-- 資產列表 -->
      <div class="list-panel">
        <!-- 節點過濾提示列：選中節點時顯示，含子樹預設開、顯式 toggle -->
        <div
          v-if="selectedNode"
          class="node-filter-bar"
        >
          <span v-if="selectedNode === 'ungrouped'">{{ $t('assets.nodeOnlyUngrouped') }}</span>
          <template v-else>
            <span>{{ $t('assets.nodePrefix', { name: selectedNode.path || selectedNode.name }) }}</span>
            <el-switch
              v-model="includeSubtree"
              :active-text="$t('assets.includeSubtree')"
              size="small"
            />
          </template>
        </div>
        <el-table
          v-loading="loading"
          :data="assetList"
          style="width: 100%"
          stripe
        >
          <el-table-column
            :label="$t('common.name')"
            min-width="200"
          >
            <template #default="{ row }">
              <div class="asset-name">
                {{ row.name }}
              </div>
              <el-tooltip
                v-if="row.description"
                :content="row.description"
                placement="top"
              >
                <div class="asset-desc">
                  {{ row.description }}
                </div>
              </el-tooltip>
            </template>
          </el-table-column>
          <!-- 協議欄：width 100＋cell padding
               6px——欄寬≠內容寬，POSTGRES chip 實測 84.2px 需內容區 ≥88px -->
          <el-table-column
            :label="$t('common.protocol')"
            width="100"
            class-name="protocol-col"
          >
            <template #default="{ row }">
              <el-tag :type="protocolTagType(row.protocol)">
                {{ row.protocol.toUpperCase() }}
              </el-tag>
            </template>
          </el-table-column>
          <!-- 主機欄：截斷恆掛 tooltip；傳輸風險行內常駐標記
              （transmission-security「恆顯示」語義，不入自訂池） -->
          <el-table-column
            :label="$t('assets.host')"
            min-width="135"
          >
            <template #default="{ row }">
              <span class="host-cell">
                <el-tooltip
                  :content="`${row.host}:${row.port}`"
                  placement="top"
                >
                  <span class="host-text">{{ row.host }}:{{ row.port }}</span>
                </el-tooltip>
                <el-tooltip
                  v-if="row.transmission_risks && row.transmission_risks.length"
                  placement="top"
                >
                  <template #content>
                    <div
                      v-for="risk in row.transmission_risks"
                      :key="risk.key"
                    >
                      {{ riskLabel(risk) }}
                    </div>
                  </template>
                  <span class="host-risk">{{ $t('assets.riskCount', row.transmission_risks.length) }}</span>
                </el-tooltip>
              </span>
            </template>
          </el-table-column>
          <!-- 池欄：預設關、齒輪開啟 -->
          <el-table-column
            v-if="showCol('username')"
            prop="username"
            :label="$t('common.user')"
            width="120"
          />
          <el-table-column
            v-if="showCol('nodes')"
            :label="$t('assets.nodesColumn')"
            min-width="150"
          >
            <template #default="{ row }">
              <el-tooltip
                v-if="(row.node_paths || []).length"
                :content="row.node_paths.join($t('common.listSeparator'))"
                placement="top"
              >
                <span class="node-paths">{{ row.node_paths.join($t('common.listSeparator')) }}</span>
              </el-tooltip>
              <span
                v-else
                class="node-paths-empty"
              >{{ $t('assets.ungrouped') }}</span>
            </template>
          </el-table-column>
          <!-- 標籤欄：chips 最多 2＋「+N」收納，
               全角色可見（一般 user 回應本就內嵌 tags） -->
          <el-table-column
            :label="$t('common.tags')"
            min-width="105"
          >
            <template #default="{ row }">
              <template v-if="assetTagList(row).length">
                <el-tag
                  v-for="tag in assetTagList(row).slice(0, 2)"
                  :key="tag"
                  size="small"
                  class="tag-chip"
                >
                  {{ tag }}
                </el-tag>
                <el-tooltip
                  v-if="assetTagList(row).length > 2"
                  :content="assetTagList(row).join($t('common.listSeparator'))"
                  placement="top"
                >
                  <el-tag
                    size="small"
                    type="info"
                  >
                    +{{ assetTagList(row).length - 2 }}
                  </el-tag>
                </el-tooltip>
              </template>
              <span
                v-else
                class="muted-dash"
              >—</span>
            </template>
          </el-table-column>
          <!-- 狀態欄：啟用＋連測縱排合併——
               連測回饋常駐可見落點（原獨立連測欄 1366 下溢出不可見）；
               僅 admin/auditor（一般 user 停用態在授權狀態 cell） -->
          <el-table-column
            v-if="isAdminOrAuditor"
            :label="$t('common.status')"
            width="100"
          >
            <template #default="{ row }">
              <div class="status-stack">
                <el-tag
                  size="small"
                  :type="row.active ? 'success' : 'info'"
                >
                  {{ row.active ? $t('common.enabled') : $t('common.disabled') }}
                </el-tag>
                <span
                  v-if="isTesting(row.id)"
                  class="conn-badge testing"
                >
                  <el-icon class="is-loading"><LoaderCircle /></el-icon>
                  {{ $t('assets.testing') }}
                </span>
                <!-- tooltip 傳原始數值（模板自帶 ms 單位）以保留完整值；
                   延遲缺失時退用不帶延遲的文案，不輸出破碎字串。
                   DB 協議另附「僅埠可達」註記（4.4） -->
                <el-tooltip
                  v-else-if="row.last_test_status"
                  :content="connBadgeTooltip(row)"
                  placement="top"
                >
                  <span
                    :class="['conn-badge', row.last_test_status === 'reachable' ? 'ok' : 'fail']"
                  >
                    <span class="conn-dot" />
                    {{ row.last_test_status === 'reachable' ? latencyText(row.last_test_latency_ms) : $t('assets.unreachable') }}
                  </span>
                </el-tooltip>
                <span
                  v-else
                  class="conn-badge muted"
                >-</span>
              </div>
            </template>
          </el-table-column>
          <!-- 授權狀態僅對一般使用者有自查意義；admin/auditor 恆為全權限不顯示。
               停用態優先呈現：一般 user 無狀態欄，
               停用資產不得顯示可連假象 -->
          <el-table-column
            v-if="!isAdminOrAuditor"
            :label="$t('assets.permissionColumn')"
            width="120"
          >
            <template #default="{ row }">
              <el-tooltip
                v-if="row.active === false"
                :content="$t('assets.disabledTooltip')"
                placement="top"
              >
                <el-tag type="info">
                  {{ $t('common.stateDisabled') }}
                </el-tag>
              </el-tooltip>
              <el-tag
                v-else-if="row.permission"
                :type="getPermissionTagType(row.permission)"
              >
                {{ getPermissionText(row.permission) }}
              </el-tag>
              <el-tag
                v-else
                type="info"
              >
                {{ $t('assets.noPermission') }}
              </el-tag>
            </template>
          </el-table-column>
          <!-- 操作欄一律 fixed right：一般 user 欄寬總和逾 1140px，常見視窗下
             表格橫向溢寬、不 fixed 的操作欄會滑出可視範圍（macOS 隱形卷軸
             使其不可發現＝根本無法連線，使用者實測踩中）。EP sticky 實作
             無溢寬時不疊壓相鄰欄（寬窄雙視窗×雙角色實測驗證） -->
          <el-table-column
            :label="$t('common.actions')"
            :width="isAdmin ? 180 : 120"
            fixed="right"
          >
            <template #default="{ row }">
              <!-- 連線入口三態：狀態由伺服端
                 access_state 單一事實源；按鈕僅是提示，點擊後仍以政策閘回應為準 -->
              <el-button
                v-if="isPendingRequest(row)"
                type="warning"
                size="small"
                link
                @click="showPendingInfo(row)"
              >
                <el-icon><Clock /></el-icon>
                {{ $t('assets.pendingBadge') }}
              </el-button>
              <el-tooltip
                v-else-if="needsRequest(row)"
                :content="$t('assets.needsRequestTooltip')"
                placement="top"
              >
                <el-button
                  type="primary"
                  size="small"
                  link
                  @click="openApplyDialog(row)"
                >
                  <el-icon><Pencil /></el-icon>
                  {{ $t('assets.applyConnect') }}
                </el-button>
              </el-tooltip>
              <!-- 入口不可用時須標示真實成因：
                 停用是資產態非權限態，對所有角色（含 admin）皆不可連，先於
                 權限判定，否則停用資產會被說成「權限不足」與同列授權狀態欄矛盾 -->
              <el-tooltip
                v-else
                :content="connectTooltipContent(row)"
                placement="top"
              >
                <span>
                  <el-button
                    type="primary"
                    size="small"
                    link
                    :disabled="!canConnect(row)"
                    @click="handleConnect(row)"
                  >
                    <el-icon><Cable /></el-icon>
                    {{ $t('common.connect') }}
                  </el-button>
                </span>
              </el-tooltip>
              <el-button
                v-if="isAdmin"
                type="primary"
                size="small"
                link
                @click="handleEdit(row)"
              >
                <el-icon><SquarePen /></el-icon>
                {{ $t('common.edit') }}
              </el-button>
              <el-dropdown
                v-if="isAdmin"
                trigger="click"
                @command="(cmd) => handleRowCommand(cmd, row)"
              >
                <el-button
                  size="small"
                  link
                >
                  {{ $t('common.more') }}
                  <el-icon><ChevronDown /></el-icon>
                </el-button>
                <template #dropdown>
                  <el-dropdown-menu>
                    <!-- 測試中態逐列獨立（4.3）：只禁用該列自己的入口，
                       其他列的測試入口仍可點擊並各自進入測試中態 -->
                    <el-dropdown-item command="accounts">
                      {{ $t('assetAccounts.manage') }}
                    </el-dropdown-item>
                    <el-dropdown-item
                      command="test"
                      :disabled="isTesting(row.id)"
                    >
                      {{ $t('assets.testConnection') }}
                    </el-dropdown-item>
                    <el-dropdown-item
                      command="delete"
                      divided
                      class="dropdown-danger"
                    >
                      {{ $t('common.delete') }}
                    </el-dropdown-item>
                  </el-dropdown-menu>
                </template>
              </el-dropdown>
            </template>
          </el-table-column>

          <template #empty>
            <EmptyState
              :title="$t('assets.emptyTitle')"
              :hint="isAdmin ? $t('assets.emptyHintAdmin') : $t('assets.emptyHintUser')"
            />
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
    </div>

    <!-- 新增/編輯對話框 -->
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
          :label="$t('common.name')"
          prop="name"
        >
          <el-input
            v-model="form.name"
            :placeholder="$t('assets.namePlaceholder')"
          />
        </el-form-item>
        <el-form-item
          :label="$t('common.protocol')"
          prop="protocol"
        >
          <el-select
            v-model="form.protocol"
            :placeholder="$t('assets.protocolPlaceholder')"
            style="width: 100%"
            @change="handleProtocolChange"
          >
            <el-option
              label="SSH"
              value="ssh"
            />
            <el-option
              label="RDP"
              value="rdp"
            />
            <el-option
              label="VNC"
              value="vnc"
            />
            <el-option
              label="MySQL"
              value="mysql"
            />
            <el-option
              label="PostgreSQL"
              value="postgres"
            />
            <el-option
              label="Redis"
              value="redis"
            />
            <el-option
              label="SQL Server"
              value="mssql"
            />
            <el-option
              label="K8s"
              value="k8s"
            />
          </el-select>
        </el-form-item>
        <el-form-item
          :label="$t('assets.host')"
          prop="host"
        >
          <el-input
            v-model="form.host"
            :placeholder="$t('assets.hostPlaceholder')"
          />
        </el-form-item>
        <el-form-item
          :label="$t('assets.port')"
          prop="port"
        >
          <el-input-number
            v-model="form.port"
            :min="1"
            :max="65535"
            style="width: 100%"
          />
        </el-form-item>
        <el-form-item
          v-if="!isPasswordOnlyProtocol(form.protocol)"
          :label="$t('common.username')"
          prop="username"
        >
          <el-input
            v-model="form.username"
            :placeholder="$t('assets.usernamePlaceholder')"
          />
        </el-form-item>
        <el-form-item
          :label="form.protocol === 'k8s' ? 'Token' : $t('common.password')"
          prop="password"
        >
          <el-input
            v-model="form.password"
            type="password"
            :placeholder="form.protocol === 'k8s' ? $t('assets.tokenPlaceholder') : $t('assets.passwordPlaceholder')"
            show-password
          />
        </el-form-item>
        <el-form-item
          v-if="['mysql', 'postgres', 'redis', 'mssql'].includes(form.protocol)"
          :label="$t('assets.dbName')"
        >
          <el-input
            v-model="form.db_name"
            :placeholder="$t('assets.dbNamePlaceholder')"
          />
        </el-form-item>
        <el-form-item
          v-if="['mysql', 'postgres', 'redis', 'mssql'].includes(form.protocol)"
          :label="$t('assets.tlsMode')"
        >
          <el-select
            v-model="form.db_tls_mode"
            style="width: 100%"
          >
            <el-option
              :label="$t('assets.tlsDefault')"
              value=""
            />
            <el-option
              :label="$t('assets.tlsDisable')"
              value="disable"
            />
            <el-option
              :label="$t('assets.tlsRequire')"
              value="require"
            />
            <el-option
              :label="$t('assets.tlsVerifyCa')"
              value="verify-ca"
            />
            <el-option
              :label="$t('assets.tlsVerifyFull')"
              value="verify-full"
            />
          </el-select>
        </el-form-item>
        <el-form-item
          v-if="['mysql', 'postgres', 'redis', 'mssql'].includes(form.protocol) && ['verify-ca', 'verify-full'].includes(form.db_tls_mode)"
          :label="$t('assets.caCert')"
        >
          <!-- mssql 的語義是「伺服器憑證釘選」（sqlcmd -J 收單張伺服器憑證），
               不是 CA bundle，故說明文字與其他三協議不共用 -->
          <el-input
            v-model="form.db_ca_cert"
            type="textarea"
            :rows="3"
            :placeholder="form.protocol === 'mssql' ? $t('assets.mssqlCaCertHint') : $t('assets.dbCaPlaceholder')"
          />
        </el-form-item>
        <!-- 查詢主控台的執行目標限制。射程只到主控台，命令列會話不受影響——
             helper 必須把這件事寫出來，否則管理者會以為填了就等於資料庫級存取控制 -->
        <el-form-item
          v-if="isDBConsoleProtocol(form.protocol)"
          :label="$t('assets.allowedDatabases')"
        >
          <el-select
            v-model="form.allowed_databases"
            multiple
            filterable
            allow-create
            default-first-option
            style="width: 100%"
            :reserve-keyword="false"
            :placeholder="$t('assets.allowedDatabasesPlaceholder')"
            data-test="allowed-databases"
          />
          <div class="form-tip">
            {{ $t('assets.allowedDatabasesScopeHint') }}
          </div>
          <div class="form-tip">
            {{ $t(`assets.allowedDatabasesCaseHint.${form.protocol}`) }}
          </div>
        </el-form-item>
        <!-- RDP 傳輸安全：預設沿現狀，
             strict 檔的修復路徑＝調 NLA＋開啟憑證驗證 -->
        <template v-if="form.protocol === 'rdp'">
          <el-form-item :label="$t('assets.rdpSecurity')">
            <el-select
              v-model="form.rdp_security"
              style="width: 100%"
            >
              <el-option
                :label="$t('assets.rdpAuto')"
                value=""
              />
              <el-option
                :label="$t('assets.rdpNla')"
                value="nla"
              />
              <el-option
                label="TLS"
                value="tls"
              />
            </el-select>
          </el-form-item>
          <el-form-item :label="$t('assets.rdpVerifyCert')">
            <el-switch v-model="form.rdp_verify_cert" />
            <span
              v-if="!form.rdp_verify_cert"
              style="margin-left: 10px; color: var(--el-color-warning); font-size: 12px"
            >{{ $t('assets.rdpVerifyWarning') }}</span>
          </el-form-item>
          <!-- 改密通道側車（沿 VNC SFTP 側車形狀：下拉為入口、子欄整組顯隱、各自具名）。
               通道與連線路徑無關：這裡設定的只有改密計劃會用到 -->
          <el-form-item
            :label="$t('assets.rotationChannel')"
            data-test="rotation-channel-item"
          >
            <el-select
              v-model="form.rotation_channel"
              style="width: 100%"
              data-test="rotation-channel"
              @change="handleRotationChannelChange"
            >
              <el-option
                :label="$t('assets.rotationChannelNone')"
                value="none"
              />
              <el-option
                :label="$t('assets.rotationChannelWinrm')"
                value="windows_winrm"
              />
              <el-option
                :label="$t('assets.rotationChannelWindowsSsh')"
                value="windows_ssh"
              />
            </el-select>
            <div class="form-tip">
              {{ $t('assets.rotationChannelHint') }}
            </div>
          </el-form-item>
          <template v-if="form.rotation_channel === 'windows_winrm'">
            <el-form-item
              :label="$t('assets.winrmScheme')"
              data-test="winrm-scheme-item"
            >
              <el-radio-group
                v-model="form.winrm_scheme"
                data-test="winrm-scheme"
                @change="handleWinrmSchemeChange"
              >
                <el-radio-button
                  v-for="scheme in WINRM_SCHEME_VALUES"
                  :key="scheme"
                  :value="scheme"
                >
                  {{ $t(`enum.winrmScheme.${scheme}`) }} {{ WINRM_DEFAULT_PORTS[scheme] }}
                </el-radio-button>
              </el-radio-group>
            </el-form-item>
            <el-form-item :label="$t('assets.winrmPort')">
              <el-input-number
                v-model="form.winrm_port"
                :min="0"
                :max="65535"
                data-test="winrm-port"
              />
              <span class="form-tip form-tip--inline">{{ $t('assets.winrmPortHint') }}</span>
            </el-form-item>
            <el-form-item
              v-if="form.winrm_scheme === 'https'"
              :label="$t('assets.winrmTlsMode')"
              data-test="winrm-tls-mode-item"
            >
              <el-radio-group
                v-model="form.winrm_tls_mode"
                data-test="winrm-tls-mode"
              >
                <el-radio-button
                  v-for="mode in WINRM_TLS_MODE_VALUES"
                  :key="mode"
                  :value="mode"
                >
                  {{ $t(`enum.winrmTlsMode.${mode}`) }}
                </el-radio-button>
              </el-radio-group>
              <div class="form-tip">
                {{ $t('assets.winrmTlsHint') }}
              </div>
            </el-form-item>
            <el-form-item
              v-if="form.winrm_scheme === 'https' && form.winrm_tls_mode === 'ca'"
              :label="$t('assets.winrmCaCert')"
              prop="winrm_ca_cert"
              data-test="winrm-ca-cert-item"
            >
              <el-input
                v-model="form.winrm_ca_cert"
                type="textarea"
                :rows="3"
                :placeholder="$t('assets.winrmCaCertPlaceholder')"
                data-test="winrm-ca-cert"
              />
              <div class="form-tip">
                {{ isEdit && form.has_winrm_ca_cert ? $t('assets.winrmCaCertKeep') : $t('assets.winrmCaCertHint') }}
              </div>
            </el-form-item>
            <el-form-item>
              <div
                class="form-tip"
                data-test="winrm-target-requirements"
              >
                {{ $t('assets.winrmTargetRequirements') }}
              </div>
            </el-form-item>
          </template>
          <el-form-item
            v-if="form.rotation_channel === 'windows_ssh'"
            :label="$t('assets.rotationSshPort')"
            data-test="rotation-ssh-port-item"
          >
            <el-input-number
              v-model="form.rotation_ssh_port"
              :min="1"
              :max="65535"
              data-test="rotation-ssh-port"
            />
            <span class="form-tip form-tip--inline">{{ $t('assets.rotationSshPortHint') }}</span>
          </el-form-item>
        </template>
        <template v-if="form.protocol === 'k8s'">
          <el-form-item
            label="Namespace"
            prop="k8s_namespace"
          >
            <el-input
              v-model="form.k8s_namespace"
              :placeholder="$t('assets.k8sNamespacePlaceholder')"
            />
          </el-form-item>
          <el-form-item :label="$t('assets.caCert')">
            <el-input
              v-model="form.k8s_ca_cert"
              type="textarea"
              :rows="3"
              :placeholder="$t('assets.k8sCaPlaceholder')"
            />
          </el-form-item>
          <el-form-item :label="$t('assets.k8sSkipTls')">
            <el-switch v-model="form.k8s_insecure_skip_tls" />
            <span
              v-if="form.k8s_insecure_skip_tls"
              style="margin-left: 10px; color: var(--el-color-danger); font-size: 12px"
            >{{ $t('assets.k8sSkipTlsWarning') }}</span>
          </el-form-item>
        </template>
        <el-form-item
          v-if="form.protocol === 'ssh'"
          :label="$t('assets.privateKey')"
          prop="private_key"
        >
          <el-input
            v-model="form.private_key"
            type="textarea"
            :rows="4"
            :placeholder="$t('assets.privateKeyPlaceholder')"
          />
        </el-form-item>
        <!-- ssh 資產的 Windows 開關＝通道 windows_ssh；關閉即回到依協議推導的 POSIX 通道 -->
        <el-form-item
          v-if="form.protocol === 'ssh'"
          :label="$t('assets.windowsSsh')"
          data-test="windows-ssh-item"
        >
          <el-switch
            v-model="windowsSshEnabled"
            data-test="windows-ssh-switch"
          />
          <span class="form-tip form-tip--inline">{{ $t('assets.windowsSshNote') }}</span>
        </el-form-item>
        <template v-if="form.protocol === 'vnc'">
          <el-form-item :label="$t('assets.sftpTransfer')">
            <el-switch v-model="form.sftp_enabled" />
            <span style="margin-left: 10px; color: var(--el-text-color-secondary); font-size: 12px">
              {{ $t('assets.sftpNote') }}
            </span>
          </el-form-item>
          <template v-if="form.sftp_enabled">
            <el-form-item :label="$t('assets.sftpPort')">
              <el-input-number
                v-model="form.sftp_port"
                :min="1"
                :max="65535"
              />
            </el-form-item>
            <el-form-item
              :label="$t('assets.sftpUsername')"
              prop="sftp_username"
            >
              <el-input
                v-model="form.sftp_username"
                :placeholder="$t('assets.sftpUsernamePlaceholder')"
              />
            </el-form-item>
            <el-form-item :label="$t('assets.sftpPassword')">
              <el-input
                v-model="form.sftp_password"
                type="password"
                show-password
                :placeholder="isEdit && form.has_sftp_password ? $t('assets.sftpPasswordKeep') : $t('assets.sftpPasswordPlaceholder')"
              />
            </el-form-item>
          </template>
        </template>
        <!-- 帳號區塊：建立時上方憑證欄位透明成為預設帳號，
            建立後才有 assetID 可掛子資源，故僅編輯態提供帳號管理入口 -->
        <el-form-item
          v-if="isEdit"
          :label="$t('assetAccounts.sectionLabel')"
        >
          <div class="asset-accounts-entry">
            <span class="asset-accounts-entry__hint">{{ $t('assetAccounts.sectionHint') }}</span>
            <el-button
              size="small"
              @click="openAccountsDialog(form)"
            >
              <el-icon><Key /></el-icon>
              {{ $t('assetAccounts.manage') }}
            </el-button>
          </div>
        </el-form-item>
        <el-form-item :label="$t('common.description')">
          <el-input
            v-model="form.description"
            type="textarea"
            :rows="3"
            :placeholder="$t('assets.descPlaceholder')"
          />
        </el-form-item>
        <!-- 標籤輸入輔助：既有標籤自動完成
            （大小寫不敏感）＋自由建立（建立前相似確認、拒逗號） -->
        <el-form-item :label="$t('common.tags')">
          <el-select
            v-model="form.tagList"
            multiple
            filterable
            allow-create
            default-first-option
            clearable
            :placeholder="$t('assets.tagPlaceholder')"
            class="tag-form-select"
            :filter-method="formTagMethod"
            @change="handleFormTagChange"
            @visible-change="resetFormTagOptions"
          >
            <el-option
              v-for="name in visibleFormTags"
              :key="name"
              :label="name"
              :value="name"
            />
          </el-select>
        </el-form-item>
        <!-- 掛載節點（多歸屬）：樹狀多選、全路徑顯示；
             空＝未分組。節點 CRUD 在資產頁左樹 -->
        <el-form-item :label="$t('assets.mountNodes')">
          <el-tree-select
            v-model="form.node_ids"
            :data="nodeSelectOptions"
            :props="{ label: 'name', children: 'children' }"
            node-key="id"
            multiple
            check-strictly
            show-checkbox
            clearable
            :placeholder="$t('assets.mountNodesPlaceholder')"
            style="width: 360px"
          />
        </el-form-item>
        <!-- 連線政策：政策掛資產本身，主要設定入口 -->
        <el-form-item :label="$t('assets.accessPolicy')">
          <!-- empty-values 排除 ''：繼承選項 value 為空字串，
               預設會被 el-select 當空值而顯示 placeholder -->
          <el-select
            v-model="form.access_policy"
            :empty-values="[null, undefined]"
            style="width: 240px"
          >
            <el-option
              :label="inheritPolicyLabel"
              value=""
            />
            <el-option
              v-for="(label, value) in accessPolicyEnumLabels"
              :key="value"
              :label="label"
              :value="value"
            />
          </el-select>
        </el-form-item>
        <el-form-item
          v-if="isEdit"
          :label="$t('common.status')"
        >
          <el-switch
            v-model="form.active"
            :active-text="$t('common.enabled')"
            :inactive-text="$t('common.disabled')"
          />
        </el-form-item>

        <!-- 主機金鑰：TOFU 指紋檢視與重置，僅編輯模式 SSH 資產 -->
        <el-form-item
          v-if="isEdit && form.protocol === 'ssh'"
          class="host-key-item"
          :label="$t('assets.hostKey')"
        >
          <div
            v-if="hostKey"
            class="host-key-box"
          >
            <div class="host-key-line">
              <span class="host-key-algo">{{ hostKey.algorithm }}</span>
              <code class="host-key-fp">{{ hostKey.fingerprint }}</code>
              <el-button
                size="small"
                link
                @click="copyFingerprint"
              >
                {{ $t('common.copy') }}
              </el-button>
            </div>
            <div class="host-key-meta">
              {{ $t('assets.hostKeyMeta', { time: formatDateTime(hostKey.created_at) }) }}
              <el-button
                size="small"
                type="danger"
                link
                @click="resetHostKey"
              >
                {{ $t('assets.resetKey') }}
              </el-button>
            </div>
          </div>
          <span
            v-else
            class="host-key-empty"
          >{{ $t('assets.hostKeyEmpty') }}</span>
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

    <!-- 申請連線：填理由段送出即連；需核准段送出後等審核 -->
    <el-dialog
      v-model="applyVisible"
      :title="$t('assets.applyConnect')"
      width="480px"
      :close-on-click-modal="false"
    >
      <el-alert
        v-if="applyTarget"
        :title="applyHint"
        type="info"
        :closable="false"
        class="apply-hint"
      />
      <el-form
        ref="applyFormRef"
        :model="applyForm"
        :rules="applyFormRules"
        label-position="top"
        @submit.prevent
      >
        <el-form-item
          :label="$t('assets.applyReasonLabel')"
          prop="reason"
        >
          <el-input
            v-model="applyForm.reason"
            type="textarea"
            :rows="3"
            maxlength="1000"
            :placeholder="$t('connect.reasonPlaceholder')"
          />
        </el-form-item>
        <el-form-item :label="$t('assets.applyDuration')">
          <el-input-number
            v-model="applyForm.duration_minutes"
            :min="1"
            :max="10080"
            style="width: 100%"
          />
        </el-form-item>
        <el-form-item :label="$t('assets.applyDateStart')">
          <el-date-picker
            v-model="applyForm.date_start"
            type="datetime"
            :placeholder="$t('assets.applyImmediate')"
            style="width: 100%"
          />
        </el-form-item>
      </el-form>
      <!-- 緊急連線次入口：僅在伺服端標註可破窗時出現，
           放對話框內非列表主按鈕（防誤觸）；點擊另開確認框說明後果 -->
      <div
        v-if="applyTarget && applyTarget.break_glass_available"
        class="break-glass-entry"
      >
        <el-divider>{{ $t('common.or') }}</el-divider>
        <el-button
          type="danger"
          plain
          size="small"
          @click="openBreakGlassDialog(applyTarget)"
        >
          <el-icon><CircleAlert /></el-icon>
          {{ $t('assets.breakGlassEntry') }}
        </el-button>
        <p class="break-glass-note">
          {{ $t('assets.breakGlassNote') }}
        </p>
      </div>
      <template #footer>
        <el-button @click="applyVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :disabled="!applyForm.reason.trim()"
          :loading="applying"
          @click="submitApply"
        >
          {{ $t('assets.applySubmit') }}
        </el-button>
      </template>
    </el-dialog>

    <!-- 緊急連線確認：強制事由、後果白話說明 -->
    <el-dialog
      v-model="breakGlassVisible"
      :title="$t('assets.breakGlassTitle')"
      width="480px"
      :close-on-click-modal="false"
    >
      <el-alert
        v-if="breakGlassTarget"
        :title="$t('assets.breakGlassAlertTitle', { name: breakGlassTarget.name })"
        type="warning"
        :closable="false"
        class="apply-hint"
      >
        <template #default>
          {{ $t('assets.breakGlassAlertBody') }}
        </template>
      </el-alert>
      <el-form
        label-position="top"
        @submit.prevent
      >
        <el-form-item :label="$t('assets.breakGlassReasonLabel')">
          <el-input
            v-model="breakGlassReason"
            type="textarea"
            :rows="3"
            maxlength="1000"
            :placeholder="$t('assets.breakGlassReasonPlaceholder')"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="breakGlassVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="danger"
          :disabled="!breakGlassReason.trim()"
          :loading="breakGlassing"
          @click="submitBreakGlass"
        >
          {{ $t('assets.breakGlassConfirm') }}
        </el-button>
      </template>
    </el-dialog>

    <!-- 標籤治理：總覽/改名/合併/刪除 -->
    <AssetTagManager
      v-model="tagManagerVisible"
      :tags="tagOptions"
      @changed="handleTagsChanged"
    />

    <!-- 資產帳號管理 -->
    <AssetAccountsDialog
      v-model="accountsDialogVisible"
      :asset-id="accountsTarget ? accountsTarget.id : null"
      :asset-name="accountsTarget ? accountsTarget.name : ''"
      :protocol="accountsTarget ? accountsTarget.protocol : ''"
    />
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, nextTick, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  Plus,
  Search,
  RefreshCw,
  SquarePen,
  Cable,
  ChevronDown,
  Clock,
  Pencil,
  CircleAlert,
  Tag,
  LoaderCircle,
  Key,
} from 'lucide-vue-next'
import { useRoute, useRouter } from 'vue-router'
import {
  getAssetList,
  getAsset,
  createAsset,
  updateAsset,
  deleteAsset,
  getAssetHostKey,
  resetAssetHostKey,
  testAssetConnection,
  getAssetGroups,
  getAssetTags,
} from '@/api/assets'
import AssetTagManager from '@/components/AssetTagManager.vue'
import AssetColumnSettings from '@/components/AssetColumnSettings.vue'
import AssetAccountsDialog from '@/components/AssetAccountsDialog.vue'
import { createAccessRequest, breakGlassConnect } from '@/api/accessRequests'
import { accessPolicyEnumLabels } from '@/utils/policyFormat'
import { riskLabel } from '@/utils/transportDisplay'
import { getSecurityPolicies } from '@/api/securityPolicies'
import { isDatabaseProtocol, isDBConsoleProtocol, isPasswordOnlyProtocol, PROTOCOL_DEFAULT_PORTS, protocolTagType } from '@/utils/protocol'
import {
  WINRM_SCHEME_VALUES,
  WINRM_TLS_MODE_VALUES,
  WINRM_DEFAULT_PORTS,
  ROTATION_SSH_DEFAULT_PORT,
  effectiveRotationChannel,
} from '@/constants/rotationChannel'
import { needsAccessRequest, isAccessPending } from '@/utils/asset-access'
import { confirmDestructive } from '@/utils/confirm'
import { formatDateTime } from '@/utils/format'
import { resolveApiError } from '@/api/error'
import { useRoles } from '@/composables/useRoles'
import { t } from '@/i18n'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import AssetNodeTree from '@/components/AssetNodeTree.vue'


// 資料狀態
const loading = ref(false)
const assetList = ref([])
const pagination = reactive({
  page: 1,
  page_size: 20,
  total: 0,
})

// 過濾表單
// 一般 user 的授權過濾由伺服端強制，前端不再自帶參數
const filterForm = reactive({
  search: '',
  protocol: '',
  active: '',
  tags: [],
})

// 標籤：清單供篩選/表單/治理共用；
// 下拉過濾大小寫不敏感（Element Plus 預設過濾大小寫敏感，需自訂）
const tagManagerVisible = ref(false)
const tagOptions = ref([])
const visibleFilterTags = ref([])
const visibleFormTags = ref([])

const tagNames = () => tagOptions.value.map((t) => t.name)
const ciFilterTags = (query) => {
  const q = (query || '').toLowerCase()
  if (!q) return tagNames()
  return tagNames().filter((n) => n.toLowerCase().includes(q))
}
const filterTagMethod = (q) => {
  visibleFilterTags.value = ciFilterTags(q)
}
const formTagMethod = (q) => {
  visibleFormTags.value = ciFilterTags(q)
}
const resetFilterTagOptions = () => {
  visibleFilterTags.value = tagNames()
}
const resetFormTagOptions = () => {
  visibleFormTags.value = tagNames()
}

const assetTagList = (row) => (row.tags ? row.tags.split(',').filter(Boolean) : [])

// 欄位自訂：池按角色、localStorage 角色分域
// versioned key（同瀏覽器交替登入不互汙）、壞值容錯回預設
const optionalColumns = ref([])
const columnPool = computed(() => {
  if (isAdminOrAuditor.value) {
    return [
      { key: 'username', label: t('common.user') },
      { key: 'nodes', label: t('assets.nodesColumn') },
    ]
  }
  return [{ key: 'nodes', label: t('assets.nodesColumn') }]
})
const columnRoleKey = () =>
  isAdmin.value ? 'admin' : isAdminOrAuditor.value ? 'auditor' : 'user'
const columnStorageKey = () => `ot-assets-columns-${columnRoleKey()}-v1`

const showCol = (key) => optionalColumns.value.includes(key)

const loadColumnPrefs = () => {
  try {
    const raw = localStorage.getItem(columnStorageKey())
    if (!raw) return
    const parsed = JSON.parse(raw)
    if (!Array.isArray(parsed)) return
    const validKeys = columnPool.value.map((c) => c.key)
    optionalColumns.value = parsed.filter((k) => validKeys.includes(k))
  } catch {
    optionalColumns.value = []
  }
}

watch(optionalColumns, (val) => {
  try {
    // 空選擇＝預設＝無偏好：移除 key（與還原預設語義一致，避免殘留 '[]'）
    if (!val.length) {
      localStorage.removeItem(columnStorageKey())
    } else {
      localStorage.setItem(columnStorageKey(), JSON.stringify(val))
    }
  } catch {
    // localStorage 不可用（隱私模式等）：欄位選擇仍生效、僅不持久
  }
})

const resetColumnPrefs = () => {
  optionalColumns.value = []
}

// 連測延遲短格式：逾 9999ms 縮顯，完整值在 tooltip
// 徽章用短格式：延遲缺失時回佔位符，
// 不得串接原始值成 `nullms`。tooltip 不得改用本函式——三語 testedAtWithLatency
// 模板已自帶 ms 單位且須呈現完整值，套用後會變成 `12msms`／`>9sms`
const latencyText = (ms) => {
  if (!Number.isFinite(ms)) {
    return '-'
  }
  return ms > 9999 ? '>9s' : `${ms}ms`
}

const loadTagOptions = async () => {
  if (!isAdminOrAuditor.value) return
  try {
    const response = await getAssetTags()
    tagOptions.value = response.data || []
    resetFilterTagOptions()
    resetFormTagOptions()
  } catch (error) {
    console.error('取得標籤清單失敗:', error)
  }
}

// 治理操作後：標籤清單與資產列表都可能變
const handleTagsChanged = () => {
  loadTagOptions()
  fetchAssetList()
}

// 建立新標籤前相似確認：canonical 相等或互為包含 → 引導用既有；
// 拒絕含半形逗號的新值（in-band 注入：落庫 join 後變兩個標籤）
const handleFormTagChange = async (vals) => {
  const last = vals[vals.length - 1]
  if (!last) return
  if (last.includes(',')) {
    form.tagList = vals.filter((v) => v !== last)
    ElMessage.warning(t('assets.tagNoComma'))
    return
  }
  const names = tagNames()
  if (names.includes(last)) return
  const lower = last.toLowerCase()
  const similar = names.find(
    (n) =>
      n.toLowerCase() === lower ||
      n.toLowerCase().includes(lower) ||
      lower.includes(n.toLowerCase())
  )
  if (!similar) return
  try {
    await ElMessageBox.confirm(
      t('assets.similarTagMessage', { name: similar }),
      t('assets.similarTagTitle'),
      {
        confirmButtonText: t('assets.useExisting', { name: similar }),
        cancelButtonText: t('assets.stillCreate', { name: last }),
        type: 'warning',
      }
    )
    form.tagList = vals
      .map((v) => (v === last ? similar : v))
      .filter((v, i, arr) => arr.indexOf(v) === i)
  } catch {
    // 仍要建立——保留使用者輸入
  }
}

// 節點過濾：null＝全部、'ungrouped'＝未分組、物件＝節點；
// 含子樹預設開、顯式 toggle
const nodeTreeRef = ref(null)
const selectedNode = ref(null)
const includeSubtree = ref(true)

const handleNodeSelect = (node) => {
  selectedNode.value = node
  pagination.page = 1
  fetchAssetList()
}

watch(includeSubtree, () => {
  if (selectedNode.value && selectedNode.value !== 'ungrouped') {
    pagination.page = 1
    fetchAssetList()
  }
})

// 資產/節點視角授權入口：預填授權精靈客體
const router = useRouter()
const route = useRoute()
const handleAuthorizeNode = (node) => {
  router.push({ path: '/authorizations', query: { node_id: node.id, node_name: node.path || node.name } })
}

// 使用者角色狀態（isAdminOrAuditor＝isPrivileged 口徑）
const { isPrivileged: isAdminOrAuditor, isAdmin } = useRoles()

// 對話框狀態
const dialogVisible = ref(false)
const isEdit = ref(false)
const submitting = ref(false)
const formRef = ref(null)

// 表單資料
const form = reactive({
  id: null,
  name: '',
  protocol: 'ssh',
  host: '',
  port: 22,
  username: '',
  password: '',
  private_key: '',
  description: '',
  tags: '',
  tagList: [],
  node_ids: [],
  access_policy: '',
  active: true,
  db_name: '',
  db_tls_mode: '',
  db_ca_cert: '',
  allowed_databases: [],
  rdp_security: '',
  rdp_verify_cert: false,
  k8s_namespace: '',
  k8s_pod: '',
  k8s_container: '',
  k8s_ca_cert: '',
  k8s_insecure_skip_tls: false,
  sftp_enabled: false,
  sftp_port: 22,
  sftp_username: '',
  sftp_password: '',
  has_sftp_password: false,
  // 改密通道側車：rdp 資產顯式選 none／windows_winrm／windows_ssh；
  // ssh 資產空字串＝依協議推導 posix_ssh，開關開啟＝windows_ssh
  rotation_channel: '',
  winrm_scheme: 'https',
  winrm_port: WINRM_DEFAULT_PORTS.https,
  winrm_tls_mode: 'system',
  winrm_ca_cert: '',
  has_winrm_ca_cert: false,
  rotation_ssh_port: ROTATION_SSH_DEFAULT_PORT,
})

// ssh 資產的 Windows 開關與通道欄位互為表裡
const windowsSshEnabled = computed({
  get: () => form.rotation_channel === 'windows_ssh',
  set: (on) => {
    form.rotation_channel = on ? 'windows_ssh' : ''
  },
})

// 側車回到出廠值：協議切換與通道切換都由此收口，殘值不跟著送出
const resetRotationChannel = (protocol) => {
  form.rotation_channel = protocol === 'rdp' ? 'none' : ''
  form.winrm_scheme = 'https'
  form.winrm_port = WINRM_DEFAULT_PORTS.https
  form.winrm_tls_mode = 'system'
  form.winrm_ca_cert = ''
  form.has_winrm_ca_cert = false
  form.rotation_ssh_port = ROTATION_SSH_DEFAULT_PORT
}

const handleRotationChannelChange = () => {
  formRef.value?.clearValidate('winrm_ca_cert')
}

// 連線方式切換時，埠仍是另一方式的預設值（或 0）才跟著換；使用者自填的埠不動
const handleWinrmSchemeChange = (scheme) => {
  const defaults = Object.values(WINRM_DEFAULT_PORTS)
  if (form.winrm_port === 0 || defaults.includes(form.winrm_port)) {
    form.winrm_port = WINRM_DEFAULT_PORTS[scheme]
  }
  if (scheme !== 'https') {
    formRef.value?.clearValidate('winrm_ca_cert')
  }
}

// 側車欄位以整份送出：通道不是 WinRM 時把 WinRM 子欄送空值，讓伺服端清空殘值；
// 編輯態的 CA 憑證留空＝維持既有（不送該鍵，伺服端視為不動）
const buildRotationChannelPayload = () => {
  const payload = {}
  if (form.protocol === 'rdp') {
    payload.rotation_channel = form.rotation_channel || 'none'
  } else {
    payload.rotation_channel = form.rotation_channel === 'windows_ssh' ? 'windows_ssh' : ''
  }
  const isWinrm = payload.rotation_channel === 'windows_winrm'
  const isHttps = isWinrm && form.winrm_scheme === 'https'
  const usesCa = isHttps && form.winrm_tls_mode === 'ca'
  payload.winrm_scheme = isWinrm ? form.winrm_scheme : ''
  payload.winrm_port = isWinrm ? form.winrm_port || 0 : 0
  payload.winrm_tls_mode = isHttps ? form.winrm_tls_mode : ''
  if (!usesCa) {
    payload.winrm_ca_cert = ''
  } else if (form.winrm_ca_cert) {
    payload.winrm_ca_cert = form.winrm_ca_cert
  }
  payload.rotation_ssh_port =
    payload.rotation_channel === 'windows_ssh' && form.protocol === 'rdp'
      ? form.rotation_ssh_port || 0
      : 0
  return payload
}

// 對話框標題
const dialogTitle = computed(() => {
  return isEdit.value ? t('assets.editTitle') : t('assets.create')
})

// 表單驗證規則（computed：切語言時錯誤訊息隨當下語言）
const formRules = computed(() => ({
  name: [{ required: true, message: t('assets.namePlaceholder'), trigger: 'blur' }],
  protocol: [{ required: true, message: t('assets.protocolPlaceholder'), trigger: 'change' }],
  host: [{ required: true, message: t('assets.ruleHostRequired'), trigger: 'blur' }],
  port: [
    { required: true, message: t('assets.rulePortRequired'), trigger: 'blur' },
    {
      type: 'number',
      min: 1,
      max: 65535,
      message: t('assets.rulePortRange'),
      trigger: 'blur',
    },
  ],
  username: [
    {
      // 僅密碼認證的協議不需使用者名稱（見 isPasswordOnlyProtocol）
      validator: (rule, value, callback) => {
        if (!isPasswordOnlyProtocol(form.protocol) && !value) {
          callback(new Error(t('assets.usernamePlaceholder')))
        } else {
          callback()
        }
      },
      trigger: 'blur',
    },
  ],
  k8s_namespace: [
    {
      validator: (rule, value, callback) => {
        if (form.protocol === 'k8s' && !value) {
          callback(new Error(t('assets.ruleNamespaceRequired')))
        } else {
          callback()
        }
      },
      trigger: 'blur',
    },
  ],
  // 指定 CA 時 PEM 必填；編輯態已有憑證則留空＝維持，不強迫重貼
  winrm_ca_cert: [
    {
      validator: (rule, value, callback) => {
        const usesCa =
          form.protocol === 'rdp' &&
          form.rotation_channel === 'windows_winrm' &&
          form.winrm_scheme === 'https' &&
          form.winrm_tls_mode === 'ca'
        if (usesCa && !value && !(isEdit.value && form.has_winrm_ca_cert)) {
          callback(new Error(t('assets.winrmCaCertRequired')))
        } else {
          callback()
        }
      },
      trigger: 'blur',
    },
  ],
}))

// 各協議預設埠號自 utils/protocol 共用（含資料庫協議 database-protocol）

// 切換協議時帶入預設埠號（僅當埠號仍為其他協議的預設值時）
const handleProtocolChange = (protocol) => {
  const defaults = Object.values(PROTOCOL_DEFAULT_PORTS)
  if (defaults.includes(form.port)) {
    form.port = PROTOCOL_DEFAULT_PORTS[protocol] || form.port
  }
  // 改密通道綁協議：切協議即回出廠值（伺服端在協議不相容時也會清空並留痕）
  resetRotationChannel(protocol)
}

// 取得資產列表
const fetchAssetList = async () => {
  loading.value = true
  try {
    const params = {
      page: pagination.page,
      page_size: pagination.page_size,
      search: filterForm.search || undefined,
      protocol: filterForm.protocol || undefined,
      active: filterForm.active !== '' ? filterForm.active : undefined,
      // 標籤篩選（僅 admin/auditor；一般 user 帶參數伺服端 400）
      tags:
        isAdminOrAuditor.value && filterForm.tags.length
          ? filterForm.tags.join(',')
          : undefined,
    }

    // 節點過濾
    if (selectedNode.value === 'ungrouped') {
      params.ungrouped = true
    } else if (selectedNode.value) {
      params.node_id = selectedNode.value.id
      if (!includeSubtree.value) params.include_subtree = false
    }

    const response = await getAssetList(params)
    assetList.value = response.data
    pagination.total = response.total
  } catch (error) {
    console.error('取得資產列表失敗:', error)
  } finally {
    loading.value = false
  }
}

// 處理過濾
const handleFilter = () => {
  pagination.page = 1
  fetchAssetList()
}

// 重置過濾
const handleResetFilter = () => {
  filterForm.search = ''
  filterForm.protocol = ''
  filterForm.active = ''
  filterForm.tags = []
  pagination.page = 1
  fetchAssetList()
}

// 處理分頁大小變更
const handleSizeChange = () => {
  fetchAssetList()
}

// 處理頁碼變更
const handlePageChange = () => {
  fetchAssetList()
}

// 權限標籤類型
const getPermissionTagType = (permission) => {
  const typeMap = {
    view: 'info',
    connect: 'success',
  }
  return typeMap[permission] || ''
}

// 權限文字（i18n：閉集走 locale key、未知值原樣顯示）
const getPermissionText = (permission) => {
  if (permission === 'view' || permission === 'connect') {
    return t(`assets.permission.${permission}`)
  }
  return permission
}

// 檢查是否可以連線：access_state（伺服端三態）優先，未標註時沿 permission 欄
const canConnect = (asset) => {
  // 停用資產一律不可連：前端擋入口、
  // 後端簽發點 403 asset_disabled 兜底；admin 同受（停用是資產態非權限態）
  if (asset.active === false) {
    return false
  }
  // 僅 Admin 保留角色短路（政策豁免帶審計、角色自動 connect 為真語義）；
  // auditor 執行期無角色自動 connect，落列表 permission 欄判定
  //（無顯式 grant 即禁用，不再顯示假入口）
  if (isAdmin.value) {
    return true
  }
  if (asset.access_state) {
    return asset.access_state === 'connectable'
  }
  return asset.permission === 'connect'
}

// 連線入口三態：需要申請／申請中——
// 停用資產一併封（申請/pending 入口不得引導向已停用資產）。
// 判準本體住 utils/asset-access.js：工作區側欄消費同一組狀態，
// 兩處各寫一份遲早會分歧
const needsRequest = (asset) =>
  needsAccessRequest(asset, { isPrivileged: isAdminOrAuditor.value })

const isPendingRequest = (asset) =>
  isAccessPending(asset, { isPrivileged: isAdminOrAuditor.value })

// 連線入口提示三態：停用 > 可連 > 無權限。
// 停用優先——canConnect 對停用資產無條件早退，若先判權限，admin 會看到
// 「權限不足」這種與事實不符的成因
const connectTooltipContent = (asset) => {
  if (asset.active === false) {
    return t('assets.disabledTooltip')
  }
  return canConnect(asset) ? t('assets.connectTooltip') : t('assets.noPermTooltip')
}

// 重置表單
const resetForm = () => {
  form.id = null
  form.name = ''
  form.protocol = 'ssh'
  form.host = ''
  form.port = 22
  form.username = ''
  form.password = ''
  form.private_key = ''
  form.description = ''
  form.tags = ''
  form.tagList = []
  form.node_ids = []
  form.access_policy = ''
  form.active = true
  form.db_name = ''
  form.db_tls_mode = ''
  form.db_ca_cert = ''
  form.allowed_databases = []
  form.rdp_security = ''
  form.rdp_verify_cert = false
  form.k8s_namespace = ''
  form.k8s_pod = ''
  form.k8s_container = ''
  form.sftp_enabled = false
  form.sftp_port = 22
  form.sftp_username = ''
  form.sftp_password = ''
  form.has_sftp_password = false
  resetRotationChannel('ssh')
  formRef.value?.clearValidate()
}

// 處理創建
const handleCreate = () => {
  resetForm()
  isEdit.value = false
  dialogVisible.value = true
}

// 掛載節點選項：平面列表組裝樹供表單 el-tree-select；
// 節點 CRUD 已收斂於左樹（AssetNodeTree），本頁僅消費
const nodeFlatList = ref([])

async function loadGroups() {
  try {
    const res = await getAssetGroups()
    nodeFlatList.value = res.data || []
  } catch (err) {
    console.error('載入節點失敗:', err)
  }
}

const nodeSelectOptions = computed(() => {
  const byId = new Map()
  nodeFlatList.value.forEach((n) => {
    byId.set(n.id, { id: n.id, name: n.path || n.name, parent_id: n.parent_id, children: [] })
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

// 連線測試（走查補入口：API 既有但前端缺引用）
//
// 測試中態逐列獨立：原本是單一 testingId ＋
// 全頁禁用測試入口，一筆資產撥測就鎖住整頁。改為 id 集合後，先完成的那筆只從
// 集合移除自己，不會清掉他列的 spinner——原註解擔心的併發問題由集合語義解決。
const testingIds = ref(new Set())
const isTesting = (id) => testingIds.value.has(id)

async function handleTest(row) {
  // 同列 single-flight：該列撥測未結束前不得重複觸發
  if (testingIds.value.has(row.id)) {
    return
  }
  testingIds.value.add(row.id)
  try {
    const res = await testAssetConnection(row.id)
    if (res.success) {
      ElMessage.success(t('assets.testSuccess', { ms: res.latency_ms }))
    } else {
      // 收到回應：以該次撥測的失敗機器碼查譯（4.2）。三層降級同 resolveApiError：
      // code 譯文 → 後端 message → 未知原因
      ElMessage.warning(t('assets.testFailed', {
        reason: resolveApiError({ code: res.code, error: res.message }, undefined, t('assets.unknownReason')),
      }))
    }
    // await 到列表重載完成才解除測試中態：
    // 不 await 會在新資料到達前就收掉 spinner，短暫閃回上一次的可達性徽章。
    // 清除仍留在 finally——fetchAssetList 自身拋錯時中態才不會永久卡住
    await fetchAssetList()
  } catch (err) {
    console.error('連線測試失敗:', err)
    // 撥測請求本身失敗（4.2）：有回應就照回應的碼呈現；沒有回應（傳輸中斷或
    // 用戶端逾時）明示「撥測未完成」，不用通用「網路錯誤」把伺服端可服務的
    // 撥測失敗誤導成網路層問題
    if (err?.response) {
      ElMessage.error(t('assets.testFailed', {
        reason: resolveApiError(err.response.data, err.response.status, t('assets.unknownReason')),
      }))
    } else {
      ElMessage.error(t('assets.testIncomplete'))
    }
  } finally {
    testingIds.value.delete(row.id)
  }
}

// 可達徽章 tooltip：DB 協議的撥測只驗 TCP 埠可達（後端 probeTCP，不做握手與認證），
// 徽章必須就地說明，否則「可達」會被讀成「憑證已驗證」（4.4）
function connBadgeTooltip(row) {
  const base = row.last_test_status === 'reachable' && Number.isFinite(row.last_test_latency_ms)
    ? t('assets.testedAtWithLatency', { time: formatDateTime(row.last_test_at), ms: row.last_test_latency_ms })
    : t('assets.testedAt', { time: formatDateTime(row.last_test_at) })
  if (row.last_test_status === 'reachable' && isDatabaseProtocol(row.protocol)) {
    return `${base}｜${t('assets.portReachableOnly')}`
  }
  return base
}

// 操作欄「更多」下拉分發（測試/刪除收納，降低欄寬與誤觸）
function handleRowCommand(command, row) {
  if (command === 'test') {
    handleTest(row)
  } else if (command === 'accounts') {
    openAccountsDialog(row)
  } else if (command === 'delete') {
    handleDelete(row)
  }
}

// 資產帳號管理：資產列與編輯對話框共用同一入口
const accountsDialogVisible = ref(false)
const accountsTarget = ref(null)

function openAccountsDialog(row) {
  accountsTarget.value = { id: row.id, name: row.name, protocol: row.protocol }
  accountsDialogVisible.value = true
}

// 主機金鑰
const hostKey = ref(null)

async function loadHostKey(assetId) {
  hostKey.value = null
  try {
    hostKey.value = await getAssetHostKey(assetId)
  } catch {
    // 404＝尚無記錄，顯示空態即可
  }
}

async function copyFingerprint() {
  try {
    await navigator.clipboard.writeText(hostKey.value.fingerprint)
    ElMessage.success(t('assets.fingerprintCopied'))
  } catch {
    ElMessage.error(t('common.copyFailed'))
  }
}

async function resetHostKey() {
  try {
    await ElMessageBox.confirm(
      t('assets.hostKeyResetConfirm'),
      t('assets.hostKeyResetTitle'),
      { type: 'warning', confirmButtonText: t('assets.hostKeyResetButton') }
    )
  } catch {
    return // 使用者取消
  }

  try {
    await resetAssetHostKey(form.id)
    hostKey.value = null
    ElMessage.success(t('assets.hostKeyResetDone'))
  } catch (error) {
    console.error('重置主機金鑰失敗:', error)
  }
}

const handleEdit = (row) => {
  resetForm()
  isEdit.value = true
  form.id = row.id
  form.name = row.name
  form.protocol = row.protocol
  form.host = row.host
  form.port = row.port
  form.username = row.username
  form.description = row.description || ''
  form.tags = row.tags || ''
  form.tagList = row.tags ? row.tags.split(',').filter(Boolean) : []
  form.node_ids = [...(row.node_ids || [])]
  form.access_policy = row.access_policy || ''
  form.active = row.active
  form.db_name = row.db_name || ''
  form.db_tls_mode = row.db_tls_mode || ''
  form.db_ca_cert = row.db_ca_cert || ''
  form.allowed_databases = [...(row.allowed_databases || [])]
  form.rdp_security = row.rdp_security || ''
  form.rdp_verify_cert = row.rdp_verify_cert || false
  form.k8s_namespace = row.k8s_namespace || ''
  form.k8s_pod = row.k8s_pod || ''
  form.k8s_container = row.k8s_container || ''
  form.sftp_enabled = row.sftp_enabled || false
  form.sftp_port = row.sftp_port || 22
  form.sftp_username = row.sftp_username || ''
  form.has_sftp_password = row.has_sftp_password || false
  // 改密通道回填：以有效通道收口（列表投影帶 effective_rotation_channel）；
  // CA 憑證本體不回顯，只以 has_winrm_ca_cert 決定「已設定，留空維持」的提示
  resetRotationChannel(row.protocol)
  const channel = effectiveRotationChannel(row)
  if (row.protocol === 'rdp') {
    form.rotation_channel = channel
  } else if (row.protocol === 'ssh') {
    form.rotation_channel = channel === 'windows_ssh' ? 'windows_ssh' : ''
  }
  if (channel === 'windows_winrm') {
    form.winrm_scheme = row.winrm_scheme || 'http'
    form.winrm_port = row.winrm_port || WINRM_DEFAULT_PORTS[form.winrm_scheme]
    form.winrm_tls_mode = row.winrm_tls_mode || 'system'
    form.has_winrm_ca_cert = row.has_winrm_ca_cert || false
  }
  if (channel === 'windows_ssh' && row.protocol === 'rdp') {
    form.rotation_ssh_port = row.rotation_ssh_port || ROTATION_SSH_DEFAULT_PORT
  }
  if (row.protocol === 'ssh') loadHostKey(row.id)
  // 注意：不填充密碼和私鑰（安全考量）
  dialogVisible.value = true
}

// 處理提交
const handleSubmit = async () => {
  try {
    await formRef.value.validate()

    // 協議改離查詢主控台支援的三種方言時，伺服端會清空允許清單。
    // 清單是管理者逐項填出來的，靜默清掉等於讓下一次改回協議時
    // 出現無從解釋的空樹——儲存前先把後果講明
    if (!isDBConsoleProtocol(form.protocol) && form.allowed_databases.length) {
      try {
        await confirmDestructive(
          t('assets.allowedDatabasesClearConfirm', { n: form.allowed_databases.length }),
          t('assets.allowedDatabasesClearTitle'),
          { confirmButtonText: t('assets.allowedDatabasesClearOk') }
        )
      } catch {
        return
      }
    }

    submitting.value = true

    const data = {
      name: form.name,
      protocol: form.protocol,
      host: form.host,
      port: form.port,
      username: form.username,
      description: form.description,
      tags: form.tagList.join(','),
      node_ids: form.node_ids,
      access_policy: form.access_policy,
    }

    if (['mysql', 'postgres', 'redis', 'mssql'].includes(form.protocol)) {
      data.db_name = form.db_name
      data.db_tls_mode = form.db_tls_mode
      data.db_ca_cert = ['verify-ca', 'verify-full'].includes(form.db_tls_mode)
        ? form.db_ca_cert
        : ''
    }

    // 允許清單只對三種 SQL 方言送出；其餘協議連空陣列都不送，
    // 交由伺服端的清空規則處理殘值
    if (isDBConsoleProtocol(form.protocol)) {
      data.allowed_databases = [...form.allowed_databases]
    }

    // RDP 傳輸安全
    if (form.protocol === 'rdp') {
      data.rdp_security = form.rdp_security
      data.rdp_verify_cert = form.rdp_verify_cert
    }

    // 改密通道側車：只有 rdp／ssh 可設，整份送出（含清空用的空值）
    if (form.protocol === 'rdp' || form.protocol === 'ssh') {
      Object.assign(data, buildRotationChannelPayload())
    }

    if (form.protocol === 'k8s') {
      data.k8s_namespace = form.k8s_namespace
      data.k8s_pod = form.k8s_pod
      data.k8s_container = form.k8s_container
      data.k8s_ca_cert = form.k8s_ca_cert
      data.k8s_insecure_skip_tls = form.k8s_insecure_skip_tls
    }

    // VNC SFTP 側車（vnc-file-transfer）：密碼留空＝後端沿用既有
    if (form.protocol === 'vnc') {
      data.sftp_enabled = form.sftp_enabled
      if (form.sftp_enabled) {
        data.sftp_port = form.sftp_port
        data.sftp_username = form.sftp_username
        if (form.sftp_password) {
          data.sftp_password = form.sftp_password
        }
      }
    }

    // 只在有值時才傳送密碼和私鑰
    if (form.password) {
      data.password = form.password
    }
    if (form.private_key) {
      data.private_key = form.private_key
    }
    if (isEdit.value) {
      data.active = form.active
    }

    if (isEdit.value) {
      await updateAsset(form.id, data)
      ElMessage.success(t('assets.updated'))
    } else {
      await createAsset(data)
      // 未掛任何節點的資產落在「未分組」，提示去向（走查實證：不提示會以為資產消失）
      ElMessage.success(form.node_ids.length ? t('assets.created') : t('assets.createdUngrouped'))
    }

    dialogVisible.value = false
    fetchAssetList()
    nodeTreeRef.value?.reloadTree()
    // 儲存可能引入新標籤：刷新清單供下拉/治理即時取用
    loadTagOptions()
  } catch (error) {
    if (error?.errors) {
      // 驗證錯誤，不需要處理
      return
    }
    console.error('提交失敗:', error)
  } finally {
    submitting.value = false
  }
}

// 處理刪除
const handleDelete = async (row) => {
  try {
    await ElMessageBox.confirm(
      t('assets.deleteConfirm', { name: row.name }),
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
    await deleteAsset(row.id)
    ElMessage.success(t('assets.deleted'))
    fetchAssetList()
    nodeTreeRef.value?.reloadTree()
  } catch (error) {
    console.error('刪除失敗:', error)
  }
}

// 處理連線
const handleConnect = (row) => {
  // 工作區入口（session-workspace）：新分頁開工作區並自動開啟該資產頁籤
  window.open(`/workspace?asset=${row.id}`, '_blank')
}

// 申請連線對話框
const applyVisible = ref(false)
const applying = ref(false)
const applyTarget = ref(null)
const applyFormRef = ref(null)
const applyForm = reactive({ reason: '', duration_minutes: 60, date_start: null })

// 理由必填且不可全空白（審核人與稽核紀錄都會看到）
const applyFormRules = computed(() => ({
  reason: [
    {
      required: true,
      validator: (rule, value, callback) => {
        if (!value || !value.trim()) {
          callback(new Error(t('assets.applyReasonRequired')))
        } else {
          callback()
        }
      },
      trigger: 'blur',
    },
  ],
}))

const applyHint = computed(() => {
  if (!applyTarget.value) return ''
  if (applyTarget.value.access_state === 'reason_required') {
    return t('assets.applyHintReason', { name: applyTarget.value.name })
  }
  return t('assets.applyHintApproval', { name: applyTarget.value.name })
})

const openApplyDialog = (row) => {
  applyTarget.value = row
  applyForm.reason = ''
  applyForm.duration_minutes = 60
  applyForm.date_start = null
  applyVisible.value = true
}

const submitApply = async () => {
  if (!applyTarget.value) return
  try {
    await applyFormRef.value.validate()
  } catch {
    return // 驗證未過，紅字就近提示
  }
  applying.value = true
  try {
    const payload = {
      asset_id: applyTarget.value.id,
      reason: applyForm.reason.trim(),
      duration_minutes: applyForm.duration_minutes,
    }
    if (applyForm.date_start) {
      payload.date_start = new Date(applyForm.date_start).toISOString()
    }
    const created = await createAccessRequest(payload)
    applyVisible.value = false
    if (created.status === 'approved') {
      // 填理由段：自動核准，直接開工作區連線（重跑標準連線流程）
      ElMessage.success(t('assets.applyApproved'))
      window.open(`/workspace?asset=${applyTarget.value.id}`, '_blank')
    } else {
      ElMessage.success(t('assets.applySubmitted'))
    }
  } catch (error) {
    // 409 重複申請 / 400 超上限等由攔截器顯示後端訊息
    console.error('送出申請失敗:', error)
  } finally {
    applying.value = false
    fetchAssetList()
  }
}

// 緊急連線：對話框內次入口觸發，強制事由，
// 成功即開工作區。開關/資格由伺服端裁決，403 由攔截器顯示白話訊息
const breakGlassVisible = ref(false)
const breakGlassing = ref(false)
const breakGlassTarget = ref(null)
const breakGlassReason = ref('')

const openBreakGlassDialog = (row) => {
  breakGlassTarget.value = row
  breakGlassReason.value = ''
  breakGlassVisible.value = true
}

const submitBreakGlass = async () => {
  if (!breakGlassTarget.value || !breakGlassReason.value.trim()) return
  breakGlassing.value = true
  try {
    await breakGlassConnect({
      asset_id: breakGlassTarget.value.id,
      reason: breakGlassReason.value.trim(),
    })
    const assetId = breakGlassTarget.value.id
    breakGlassVisible.value = false
    applyVisible.value = false
    ElMessage.success(t('assets.breakGlassStarted'))
    window.open(`/workspace?asset=${assetId}`, '_blank')
  } catch (error) {
    // 403 未開放/無資格、409 重複破窗等由攔截器顯示後端訊息
    console.error('緊急連線失敗:', error)
  } finally {
    breakGlassing.value = false
    fetchAssetList()
  }
}

// 申請中：說明現況＋導向我的申請（按鈕不鎖死——狀態過時時後端閘會自癒）
const showPendingInfo = async (row) => {
  const key = row.pending_request_id ? 'assets.pendingInfoWithId' : 'assets.pendingInfo'
  try {
    await ElMessageBox.confirm(
      t(key, { name: row.name, id: row.pending_request_id }),
      t('assets.pendingInfoTitle'),
      {
        confirmButtonText: t('assets.viewMyRequests'),
        cancelButtonText: t('connect.ok'),
        type: 'info',
      }
    )
    window.location.href = '/my-requests'
  } catch {
    // 知道了：僅關閉
  }
}

// 資產連線政策的繼承文案：表單開啟時查一次
// 全域預設，「跟隨全域設定（目前：X）」動態回顯；查失敗降級為無值文案
//（admin-only 端點，開編輯表單者必為 admin）
const globalAccessPolicy = ref('')
const loadGlobalAccessPolicy = async () => {
  try {
    const res = await getSecurityPolicies()
    const policy = (res.data || []).find((p) => p.key === 'access_policy_default')
    globalAccessPolicy.value = policy ? policy.value : ''
  } catch (error) {
    console.error('載入全域存取政策失敗:', error)
    globalAccessPolicy.value = ''
  }
}
watch(dialogVisible, (visible) => {
  if (visible) loadGlobalAccessPolicy()
})

const inheritPolicyLabel = computed(() => {
  const current = accessPolicyEnumLabels[globalAccessPolicy.value]
  return current
    ? t('assets.inheritPolicyWithCurrent', { value: current })
    : t('assets.inheritPolicy')
})

// 掛載時取得資料
onMounted(() => {
  fetchAssetList()
  // 分組選項與分組管理對話框共用：掛載即載入（原本只在增刪組後載入，
  // 新 session 開頁分組下拉恆空、對話框誤顯「尚無分組」）
  loadGroups()
  // 標籤清單（篩選下拉/表單自動完成/治理共用；僅 admin/auditor 端點可達）
  loadTagOptions()
  // 欄位偏好：角色解析之後載入（key 角色分域）
  loadColumnPrefs()
  openEditFromQuery()
})

// 資產編輯深連結：?edit=<id> 直開編輯框並捲至
// 主機金鑰欄位（終端 host key 拒線引導的落點）。404（不存在或不可視）由攔截器
// 統一 toast「資產不存在」，此處只清參數——不洩漏存在性
async function openEditFromQuery() {
  // route/router 缺席防禦（單測掛載無 router 注入）：無 query 即無深連結，直接略過
  const id = Number(route?.query?.edit)
  if (!id) return
  try {
    const asset = await getAsset(id)
    handleEdit(asset)
    await nextTick()
    document.querySelector('.host-key-item')?.scrollIntoView({ block: 'center' })
  } catch (err) {
    console.error('[Assets] 編輯深連結載入失敗:', err)
  } finally {
    const query = { ...route.query }
    delete query.edit
    router?.replace({ query })
  }
}
</script>

<style scoped>
.assets {
  /* MainLayout already provides padding via --ot-space-lg */
}

.asset-name {
  color: var(--ot-text-primary);
}

.muted-dash {
  color: var(--ot-text-disabled);
}

.asset-desc {
  color: var(--ot-text-secondary);
  font-size: 12px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 100%;
}


.filter-bar {
  margin-bottom: var(--ot-space-md);
  padding: var(--ot-space-md);
  background: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.tree-table-layout {
  display: flex;
  gap: var(--ot-space-md);
  align-items: flex-start;
}

.node-filter-bar {
  display: flex;
  align-items: center;
  gap: var(--ot-space-md);
  padding: 6px 0;
  margin-bottom: var(--ot-space-xs);
  color: var(--ot-text-secondary);
  font-size: 13px;
}

.node-paths-empty {
  color: var(--ot-text-secondary);
}

.list-panel {
  flex: 1;
  min-width: 0;
}

.list-panel-legacy {
  background: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  padding: var(--ot-space-md);
  min-height: 400px;
}

.pagination {
  margin-top: var(--ot-space-md);
  display: flex;
  justify-content: flex-end;
}

.host-key-box {
  width: 100%;
  font-size: 12px;
}

.host-key-line {
  display: flex;
  align-items: center;
  gap: 8px;
}

.host-key-algo {
  color: var(--el-text-color-secondary);
}

.host-key-fp {
  word-break: break-all;
  background: var(--el-fill-color);
  padding: 2px 6px;
  border-radius: 3px;
}

.host-key-meta,
.host-key-empty {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}

.apply-hint {
  margin-bottom: var(--ot-space-md);
}

/* 表單欄位下方的說明句：兩句都是判讀該欄位所必需，
   不塞進 placeholder（placeholder 一輸入就消失） */
.form-tip {
  width: 100%;
  margin-top: 4px;
  font-size: 12px;
  line-height: 1.5;
  color: var(--el-text-color-secondary);
}

/* 與數字輸入或開關同列的短說明 */
.form-tip--inline {
  width: auto;
  margin-top: 0;
  margin-left: 10px;
}

.break-glass-entry {
  text-align: center;
}

.break-glass-note {
  margin: 8px 0 0;
  font-size: 12px;
  color: var(--el-text-color-secondary);
  line-height: 1.5;
}

.manage-groups-btn {
  margin-left: 8px;
}

.tag-chip {
  margin-right: 4px;
}

/* 協議欄專用緊縮 padding：el-table .cell 預設 12px×2 吃掉 24px，
   POSTGRES chip（實測 84.2px）在 width 100 下需內容區 ≥88px */
.list-panel :deep(.protocol-col .cell) {
  padding-left: 6px;
  padding-right: 6px;
}

/* 狀態欄縱排：啟用 tag＋連測徽章 */
.status-stack {
  display: flex;
  flex-direction: column;
  gap: 2px;
  align-items: flex-start;
}

.conn-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.conn-badge .conn-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
}

.conn-badge.ok {
  color: var(--el-color-success);
}

.conn-badge.ok .conn-dot {
  background: var(--el-color-success);
}

.conn-badge.fail {
  color: var(--el-color-danger);
}

.conn-badge.fail .conn-dot {
  background: var(--el-color-danger);
}

.conn-badge.testing {
  color: var(--el-color-primary);
}

.conn-badge.muted {
  color: var(--el-text-color-placeholder);
}

/* 主機欄：截斷＋行內傳輸風險常駐標記 */
.host-cell {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  max-width: 100%;
}

.host-text {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.host-risk {
  flex-shrink: 0;
  font-size: 12px;
  color: var(--el-color-warning);
  border: 1px solid var(--el-color-warning);
  border-radius: 3px;
  padding: 0 4px;
  line-height: 18px;
  cursor: help;
}

/* 節點欄截斷（tooltip 恆掛） */
.node-paths {
  display: inline-block;
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  vertical-align: bottom;
}

/* 自選加欄溢寬時卷軸常顯：作用域限資產列表，不 hover 才現形 */
.list-panel :deep(.el-scrollbar__bar.is-horizontal) {
  opacity: 1;
}

.column-settings-item {
  margin-right: 0;
}

.tag-filter-select {
  min-width: 180px;
}

.tag-form-select {
  width: 100%;
}

.asset-accounts-entry {
  display: flex;
  align-items: center;
  gap: 12px;
  width: 100%;
}

.asset-accounts-entry__hint {
  flex: 1;
  font-size: 12px;
  color: var(--el-text-color-secondary);
  line-height: 1.5;
}

</style>

<style>
/* 下拉選單 teleport 至 body，scoped 樣式打不到，須全域 */
.el-dropdown-menu__item.dropdown-danger {
  color: var(--el-color-danger);
}
</style>
