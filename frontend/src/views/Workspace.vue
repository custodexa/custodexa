<template>
  <div class="workspace">
    <!-- 40px 頂欄：連線頁寸土寸金，頂欄只留側欄開關與會話動作，其餘垂直空間讓給終端 -->
    <div class="workspace-header">
      <el-button
        size="small"
        text
        class="header-icon"
        @click="toggleSidebar"
      >
        {{ sidebarCollapsed ? '☰' : '◀' }}
      </el-button>
      <el-link
        class="brand-link"
        :underline="false"
        @click="openSystem"
      >
        {{ BRAND.name }}
      </el-link>
      <span class="workspace-hint">{{ $t('menu.workspace') }}</span>
      <!-- 語言切換：工作區是長駐連線面，切語言免 reload 不斷線 -->
      <el-dropdown
        class="workspace-lang"
        @command="setLanguage"
      >
        <span class="workspace-lang-label">{{ LOCALE_LABELS[locale] }}</span>
        <template #dropdown>
          <el-dropdown-menu>
            <el-dropdown-item
              v-for="l in SUPPORTED_LOCALES"
              :key="l"
              :command="l"
              :disabled="l === locale"
            >
              {{ LOCALE_LABELS[l] }}
            </el-dropdown-item>
          </el-dropdown-menu>
        </template>
      </el-dropdown>
    </div>

    <div class="workspace-body">
      <!-- 可收合資產側欄 -->
      <div
        v-show="!sidebarCollapsed"
        class="workspace-sidebar"
      >
        <el-input
          v-model="assetFilter"
          size="small"
          :placeholder="$t('workspace.searchAssets')"
          clearable
        />
        <div class="asset-list">
          <template
            v-for="section in groupedAssets"
            :key="section.name"
          >
            <div
              v-if="groupedAssets.length > 1"
              class="asset-group-label"
            >
              {{ section.name }}
            </div>
            <div
              v-for="item in section.assets"
              :key="item.id"
              class="asset-item"
              :class="{ 'is-gated': entryState(item) !== 'open' }"
              :data-access-state="entryState(item)"
              @click="onAssetClick(item)"
            >
              <!-- 名稱是選錯資產的唯一防線：截斷時仍要能以滑鼠取得全名 -->
              <span
                class="asset-item-name"
                :title="item.name"
              >{{ item.name }}</span>
              <!-- 需申請／審核中：整列與主控台鈕都不發簽發，指引回資產頁；
                   本頁是純連線面，不內嵌申請流 -->
              <el-tooltip
                v-if="entryState(item) !== 'open'"
                :content="entryTooltip(item)"
                placement="top"
              >
                <el-icon class="asset-item-gate">
                  <Lock v-if="entryState(item) === 'locked'" />
                  <Clock v-else />
                </el-icon>
              </el-tooltip>
              <!-- 查詢主控台入口：只對三種 SQL 方言出現，
                   與同列的命令列入口同一組存取狀態判準。
                   側欄只有 220 px，入口用文字會把資產名擠到剩兩三個字元
                   （日文最甚），所以走與分頁型別同一顆圖示，名稱由 tooltip 給 -->
              <el-tooltip
                v-if="isDBConsoleProtocol(item.protocol)"
                :content="entryState(item) === 'open'
                  ? $t('workspace.openConsole')
                  : entryTooltip(item)"
                placement="top"
                :enterable="false"
              >
                <span class="asset-item-console">
                  <el-link
                    type="primary"
                    :underline="false"
                    :disabled="entryState(item) !== 'open'"
                    :aria-label="$t('workspace.console')"
                    data-test="console-entry"
                    @click.stop="openConsoleTab(item)"
                  >
                    <el-icon><Database /></el-icon>
                  </el-link>
                </span>
              </el-tooltip>
              <el-tag
                size="small"
                :type="protocolTagType(item.protocol)"
              >
                {{ item.protocol.toUpperCase() }}
              </el-tag>
            </div>
          </template>
          <div
            v-if="!filteredAssets.length"
            class="asset-empty"
          >
            {{ $t('workspace.noMatchingAssets') }}
          </div>
        </div>
      </div>

      <!-- 會話頁籤區 -->
      <div class="workspace-tabs">
        <el-tabs
          v-if="tabs.length"
          v-model="activeKey"
          type="border-card"
          closable
          @tab-remove="closeTab"
        >
          <el-tab-pane
            v-for="tab in tabs"
            :key="tab.key"
            :name="tab.key"
          >
            <template #label>
              <span
                :class="{ 'tab-disconnected': isDisconnected(tab) }"
                @contextmenu.prevent="openTabMenu($event, tab.key)"
              >
                <!-- 同一個資產可同時開命令列與主控台，標題文字相同：
                     分頁型別要靠圖示分辨 -->
                <el-tooltip
                  v-if="tab.kind === 'console'"
                  :content="$t('workspace.consoleTabTip')"
                  placement="bottom"
                  :enterable="false"
                >
                  <el-icon class="tab-kind-icon"><Database /></el-icon>
                </el-tooltip>
                {{ isDisconnected(tab) ? $t('workspace.tabDisconnected', { label: tabLabel(tab) }) : tabLabel(tab) }}
              </span>
            </template>
          </el-tab-pane>
        </el-tabs>

        <!-- 會話工具：置於頁籤列右端既有空白，
             操作目前啟用文字終端會話；檔案/監控為 SSH 專屬能力 -->
        <div
          v-if="activeTermTab"
          class="tabbar-tools"
        >
          <!-- K8s 連線 context（解決「看不出在哪個 ns/pod/container」）-->
          <span
            v-if="activeTermTab.protocol === 'k8s'"
            class="k8s-ctx"
          >
            <span class="k8s-ctx__seg"><b>ns</b> {{ activeTermTab.k8sNamespace }}</span>
            <span class="k8s-ctx__seg"><b>pod</b> {{ activeTermTab.k8sPod }}</span>
            <span
              v-if="activeTermTab.k8sContainer"
              class="k8s-ctx__seg"
            ><b>ctr</b> {{ activeTermTab.k8sContainer }}</span>
            <span
              class="k8s-ctx__badge"
              :class="activeTermTab.k8sMode === 'logs' ? 'is-logs' : 'is-exec'"
            >{{ activeTermTab.k8sMode === 'logs' ? $t('workspace.k8sLogsReadonly') : 'exec' }}</span>
          </span>
          <el-tooltip :content="$t('workspace.shareSession')">
            <button
              type="button"
              class="tool-btn"
              :aria-label="$t('workspace.shareSession')"
              @click="activeTermTab.shareVisible = true"
            >
              <el-icon><Share2 /></el-icon>
            </button>
          </el-tooltip>
          <el-tooltip
            v-if="activeTermTab.protocol === 'ssh'"
            :content="$t('workspace.fileManager')"
          >
            <button
              type="button"
              class="tool-btn"
              :aria-label="$t('workspace.fileManager')"
              @click="activeTermTab.fileVisible = true"
            >
              <el-icon><FolderOpen /></el-icon>
            </button>
          </el-tooltip>
          <el-tooltip
            v-if="activeTermTab.protocol === 'ssh'"
            :content="$t('workspace.systemMonitor')"
          >
            <button
              type="button"
              class="tool-btn"
              :aria-label="$t('workspace.systemMonitor')"
              @click="activeTermTab.statsVisible = true"
            >
              <el-icon><Activity /></el-icon>
            </button>
          </el-tooltip>
          <el-tooltip :content="$t('workspace.commandSnippets')">
            <button
              type="button"
              class="tool-btn"
              :aria-label="$t('workspace.commandSnippets')"
              @click="activeTermTab.snippetVisible = true"
            >
              <el-icon><FileCode /></el-icon>
            </button>
          </el-tooltip>
          <el-tooltip
            v-if="activeTermTab.protocol === 'k8s' && activeTermTab.k8sMode !== 'logs'"
            :content="$t('workspace.uploadTooltip')"
          >
            <button
              type="button"
              class="tool-btn"
              :aria-label="$t('workspace.uploadAria')"
              @click="triggerK8sUpload"
            >
              <el-icon><Upload /></el-icon>
            </button>
          </el-tooltip>
          <el-tooltip
            v-if="activeTermTab.protocol === 'k8s' && activeTermTab.k8sMode !== 'logs'"
            :content="$t('workspace.downloadFromContainer')"
          >
            <button
              type="button"
              class="tool-btn"
              :aria-label="$t('workspace.downloadFromContainer')"
              @click="triggerK8sDownload"
            >
              <el-icon><Download /></el-icon>
            </button>
          </el-tooltip>
        </div>
        <input
          ref="k8sFileInput"
          type="file"
          style="display: none"
          @change="onK8sFileChange"
        >

        <!-- 會話內容常駐 DOM、v-show 切換（保活不斷線） -->
        <div class="tab-panels">
          <div
            v-for="tab in tabs"
            v-show="tab.key === activeKey"
            :key="tab.key + '-' + (tab.epoch || 0)"
            class="tab-panel"
          >
            <TerminalWatermark />
            <!-- 查詢主控台：與同資產的命令列分頁是兩種載體，先於協議判斷分流 -->
            <DbConsole
              v-if="tab.kind === 'console'"
              :asset-id="tab.assetId"
              :account-id="tab.accountId"
              :asset-name="tab.name"
              :allowed-databases="tab.allowedDatabases"
              :previous-session-id="tab.previousSessionId"
              :pending-event-id="tab.pendingEventId"
              :pending-sql="tab.pendingSql"
              :initial-sql="tab.sql"
              @status-change="tab.status = $event"
              @session-id="tab.sessionId = $event"
              @sql-change="tab.sql = $event"
              @pending-change="onConsolePending(tab, $event)"
              @unsettled-change="tab.unsettled = $event"
            />
            <!-- 文字終端類（SSH 與資料庫 CLI，database-protocol）共用 xterm 終端與審計鏈；
                 檔案管理/系統監控為 SSH 專屬（SFTP 與 /proc 指標） -->
            <template v-else-if="isTextTerminal(tab.protocol)">
              <SshTerminal
                :ref="(el) => setTerminalRef(tab.key, el)"
                :asset-id="tab.assetId"
                :protocol="tab.protocol"
                :account-id="tab.accountId"
                :k8s-pod="tab.k8sPod"
                :k8s-container="tab.k8sContainer"
                :k8s-mode="tab.k8sMode"
                @status-change="tab.status = $event"
                @session-id="tab.sessionId = $event"
              />
              <!-- 自會話分頁進 SFTP 沿用該 session 的帳號：
                   後端以 session_id 取帳號快照再依現行授權複查；
                   sessionId 尚未回傳（撥號中）時退回預設帳號，與獨立入口同語義 -->
              <FileManager
                v-if="tab.protocol === 'ssh'"
                v-model="tab.fileVisible"
                :asset-id="tab.assetId"
                :session-id="tab.sessionId"
                :account-username="tab.sessionId ? tab.accountUsername : ''"
              />
              <SnippetDrawer
                v-model="tab.snippetVisible"
                @use="useSnippet(tab.key, $event)"
              />
              <SessionStatsPanel
                v-if="tab.protocol === 'ssh'"
                v-model="tab.statsVisible"
                :session-id="tab.sessionId"
              />
              <ShareDialog
                v-model="tab.shareVisible"
                :session-id="tab.sessionId"
              />
            </template>
            <GuacamoleClient
              v-else
              :asset-id="tab.assetId"
              :account-id="tab.accountId"
              :protocol="tab.protocol"
              :asset-name="tab.name"
              @status-change="tab.status = $event"
            />
          </div>

          <div
            v-if="!tabs.length"
            class="tabs-empty"
          >
            <el-empty :description="$t('workspace.emptyTabs')" />
          </div>
        </div>
      </div>
    </div>

    <!-- 頁籤右鍵選單 -->
    <ul
      v-if="tabMenu.visible"
      class="tab-context-menu"
      :style="{ left: tabMenu.x + 'px', top: tabMenu.y + 'px' }"
    >
      <li @click="menuReconnect">
        {{ $t('workspace.menuReconnect') }}
      </li>
      <li @click="menuDuplicate">
        {{ $t('workspace.menuDuplicate') }}
      </li>
      <li class="menu-divider" />
      <li @click="menuClose">
        {{ $t('workspace.menuClose') }}
      </li>
      <li @click="menuCloseOthers">
        {{ $t('workspace.menuCloseOthers') }}
      </li>
      <li @click="menuCloseLeft">
        {{ $t('workspace.menuCloseLeft') }}
      </li>
      <li @click="menuCloseRight">
        {{ $t('workspace.menuCloseRight') }}
      </li>
      <li @click="menuCloseAll">
        {{ $t('workspace.menuCloseAll') }}
      </li>
    </ul>

    <!-- K8s 連線時選 pod 選擇器（全域單例） -->
    <K8sPodSelector
      v-model="podSelectorVisible"
      :asset-id="pendingK8sAsset ? pendingK8sAsset.id : null"
      :asset-name="pendingK8sAsset ? pendingK8sAsset.name : ''"
      :asset-namespace="pendingK8sAsset ? pendingK8sAsset.k8s_namespace : ''"
      @confirm="onPodSelected"
    />

    <!-- 多帳號資產連線時選帳號（全域單例） -->
    <AccountSelector
      v-model="accountSelectorVisible"
      :asset-name="pendingAccountAsset ? pendingAccountAsset.name : ''"
      :accounts="pendingAccounts"
      @confirm="onAccountSelected"
    />
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onBeforeUnmount, watch, nextTick } from 'vue'
import { useI18n } from 'vue-i18n'
import { BRAND } from '@/brand'
import { SUPPORTED_LOCALES, LOCALE_LABELS, setLanguage, t } from '@/i18n'
// 工具列 icon 與側欄同取 lucide-vue-next，維持全站 icon 體系一致
import { Share2, FolderOpen, Activity, FileCode, Upload, Download, Database, Lock, Clock } from 'lucide-vue-next'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useRoute } from 'vue-router'
import Sortable from 'sortablejs'
import SshTerminal from '@/components/SshTerminal.vue'
import DbConsole from '@/components/DbConsole/DbConsole.vue'
import K8sPodSelector from '@/components/K8sPodSelector.vue'
import AccountSelector from '@/components/AccountSelector.vue'
import GuacamoleClient from '@/components/GuacamoleClient.vue'
import FileManager from '@/components/FileManager.vue'
import SnippetDrawer from '@/components/SnippetDrawer.vue'
import SessionStatsPanel from '@/components/SessionStatsPanel.vue'
import ShareDialog from '@/components/ShareDialog.vue'
import TerminalWatermark from '@/components/TerminalWatermark.vue'
import { getAssetList, getAsset, uploadK8sFile, downloadK8sFile } from '@/api/assets'
import { listAssetAccounts } from '@/api/assetAccounts'
import { resolveApiError } from '@/api/error'
import { moveItem } from '@/utils/move-item'
import { isTextTerminal, isDBConsoleProtocol, protocolTagType } from '@/utils/protocol'
import { closeOthers, closeLeft, closeRight, closeAll } from '@/utils/tab-close'
import { assetEntryState } from '@/utils/asset-access'
import { confirmDestructive } from '@/utils/confirm'
import { useRoles } from '@/composables/useRoles'

const SIDEBAR_COLLAPSED_KEY = 'workspace-sidebar-collapsed'

const { locale } = useI18n()
const route = useRoute()

const assets = ref([])
const assetFilter = ref('')
const sidebarCollapsed = ref(localStorage.getItem(SIDEBAR_COLLAPSED_KEY) === '1')

// 頁籤狀態：key 用遞增序號，同資產可多開
const tabs = ref([])
const activeKey = ref('')
let tabSeq = 0

// 目前啟用的文字終端會話籤（頁籤列工具操作對象）。
// 主控台分頁的協議雖同屬文字終端類，但它沒有 xterm 載體，
// 分享／片段／檔案／指標四個工具對它一律不適用——排除即自然隱藏
const activeTermTab = computed(() =>
  tabs.value.find(
    (t) => t.key === activeKey.value && t.kind !== 'console' && isTextTerminal(t.protocol)
  ) || null
)

// 側欄的存取狀態分化：命令列與主控台兩個入口共用同一判準，不單做一邊
const { isPrivileged } = useRoles()

const entryState = (asset) => assetEntryState(asset, { isPrivileged: isPrivileged.value })

const entryTooltip = (asset) =>
  entryState(asset) === 'pending'
    ? t('workspace.accessPendingTip')
    : t('workspace.accessLockedTip')

const filteredAssets = computed(() => {
  const term = assetFilter.value.trim().toLowerCase()
  if (!term) return assets.value
  return assets.value.filter((a) => a.name.toLowerCase().includes(term))
})

// 按節點路徑分節：多歸屬資產在每個掛載節點下
// 各出現一次（與資產頁樹一致）；單一節（全未分組）時不顯示節標題
const groupedAssets = computed(() => {
  const ungroupedLabel = t('assets.ungrouped')
  const sections = new Map()
  for (const a of filteredAssets.value) {
    const paths = (a.node_paths || []).length ? a.node_paths : [ungroupedLabel]
    for (const name of paths) {
      if (!sections.has(name)) sections.set(name, [])
      sections.get(name).push(a)
    }
  }
  // 未分組永遠排最後，其餘按路徑字典序（樹形鄰近性）
  return [...sections.entries()]
    .sort((x, y) => {
      const xu = x[0] === ungroupedLabel
      const yu = y[0] === ungroupedLabel
      if (xu !== yu) return xu - yu
      return x[0].localeCompare(y[0])
    })
    .map(([name, list]) => ({ name, assets: list }))
})

// SSH 終端元件 ref（terminal-snippets）：以 tab.key 索引，供片段注入
const terminalRefs = new Map()

function setTerminalRef(key, el) {
  if (el) terminalRefs.set(key, el)
  else terminalRefs.delete(key)
}

function useSnippet(key, content) {
  terminalRefs.get(key)?.sendText(content)
}

// 頁籤右鍵選單
const tabMenu = ref({ visible: false, x: 0, y: 0, key: '' })

function openTabMenu(event, key) {
  tabMenu.value = { visible: true, x: event.clientX, y: event.clientY, key }
}

function hideTabMenu() {
  if (tabMenu.value.visible) tabMenu.value = { ...tabMenu.value, visible: false }
}

function onGlobalKeydown(e) {
  if (e.key === 'Escape') hideTabMenu()
}

function menuReconnect() {
  const tab = tabs.value.find((t) => t.key === tabMenu.value.key)
  if (tab) {
    // epoch 遞增強制面板 remount 重新撥接。
    // 主控台另交還上一場會話：新面板首則要帶著它去問未收束單位的下場
    tabs.value = tabs.value.map((t) =>
      t.key === tab.key
        ? {
          ...t,
          epoch: (t.epoch || 0) + 1,
          status: 'connecting',
          previousSessionId: t.kind === 'console' ? t.sessionId : t.previousSessionId
        }
        : t
    )
  }
  hideTabMenu()
}

function menuDuplicate() {
  const tab = tabs.value.find((t) => t.key === tabMenu.value.key)
  if (tab) {
    const asset = { id: tab.assetId, name: tab.name, protocol: tab.protocol }
    if (tab.protocol === 'k8s') {
      // k8s 仍走 pod 選擇器（pod 短命，沿用原 pod 未必還在）
      openTab(asset)
    } else {
      // 沿用原分頁的帳號：再問一次帳號等於把「複製分頁」降級成「重新開啟」
      createTab(
        { ...asset, allowed_databases: tab.allowedDatabases },
        null,
        tab.accountId ? { id: tab.accountId, username: tab.accountUsername } : null,
        tab.accountPicked,
        tab.kind
      )
    }
  }
  hideTabMenu()
}

function menuClose() {
  closeTab(tabMenu.value.key)
  hideTabMenu()
}

// 關閉會結束會話。主控台分頁若有語句還在跑、或交易開著沒收束，
// 直接關掉就把「這筆到底生效了沒」丟給使用者自己猜——先問，並把找回路徑講明
function needsCloseConfirm(tab) {
  return tab.kind === 'console' && tab.unsettled === true
}

function confirmClosing(closing, commit) {
  const unsettled = closing.filter(needsCloseConfirm)
  if (!unsettled.length) {
    // 無未收束狀態：維持既有的「關即關」，不多一道確認
    commit()
    return
  }
  confirmDestructive(
    t('workspace.closeUnsettledMessage', { n: unsettled.length }),
    t('workspace.closeUnsettledTitle'),
    { confirmButtonText: t('workspace.closeUnsettledConfirm') }
  )
    .then(commit)
    .catch(() => { /* 取消：分頁與會話原樣保留 */ })
}

function applyCloseResult({ tabs: nextTabs, activeKey: nextActive }) {
  const keep = new Set(nextTabs.map((t) => t.key))
  const closing = tabs.value.filter((t) => !keep.has(t.key))
  hideTabMenu()
  confirmClosing(closing, () => {
    tabs.value = nextTabs
    activeKey.value = nextActive
  })
}

function menuCloseOthers() {
  applyCloseResult(closeOthers(tabs.value, tabMenu.value.key))
}

function menuCloseLeft() {
  applyCloseResult(closeLeft(tabs.value, tabMenu.value.key, activeKey.value))
}

function menuCloseRight() {
  applyCloseResult(closeRight(tabs.value, tabMenu.value.key, activeKey.value))
}

function menuCloseAll() {
  applyCloseResult(closeAll())
}

// 頁籤拖曳排序：Sortable 掛 el-tabs nav，
// onEnd 先還原 DOM 再不可變重排，交 Vue 重渲染
let tabSortable = null

function setupTabSortable() {
  const nav = document.querySelector('.workspace-tabs .el-tabs__nav')
  if (!nav || tabSortable) return
  tabSortable = Sortable.create(nav, {
    animation: 150,
    delay: 150,
    delayOnTouchOnly: true,
    onEnd: ({ oldIndex, newIndex, item, from }) => {
      // 還原 Sortable 的 DOM 變動，避免與 vdom 重渲染錯位
      const children = Array.from(from.children)
      children.splice(newIndex, 1)
      from.insertBefore(item, children[oldIndex] || null)
      tabs.value = moveItem(tabs.value, oldIndex, newIndex)
    },
  })
}

watch(
  () => tabs.value.length,
  async (len, prevLen) => {
    if (len > 0 && prevLen === 0) {
      // el-tabs 由 v-if 初次掛載後才有 nav DOM
      await nextTick()
      setupTabSortable()
    } else if (len === 0 && tabSortable) {
      tabSortable.destroy()
      tabSortable = null
    }
  }
)

onBeforeUnmount(() => {
  if (tabSortable) {
    tabSortable.destroy()
    tabSortable = null
  }
  document.removeEventListener('click', hideTabMenu)
  document.removeEventListener('keydown', onGlobalKeydown)
})

onMounted(async () => {
  document.addEventListener('click', hideTabMenu)
  document.addEventListener('keydown', onGlobalKeydown)
  await loadAssets()

  // ?asset= 自動開啟首個頁籤
  const initialAssetId = route.query.asset
  if (initialAssetId) {
    try {
      const asset = await getAsset(initialAssetId)
      openTab(asset)
    } catch (err) {
      console.error('[Workspace] 開啟指定資產失敗:', err)
    }
  }
})

async function loadAssets() {
  try {
    const response = await getAssetList({ page: 1, page_size: 100 })
    assets.value = (response.data || []).filter((a) => a.active !== false)
  } catch (err) {
    console.error('[Workspace] 載入資產列表失敗:', err)
  }
}

// K8s 連線時選 pod：開籤前先跳選擇器，選定 pod/container/模態後才建終端籤
const podSelectorVisible = ref(false)
const pendingK8sAsset = ref(null)

// 多帳號資產連線時選帳號：開籤前先取有效授權帳號清單，
// 兩個以上才彈選擇器；k8s 固定單一預設帳號（RULE_ACCOUNT_K8S_DEFAULT_ONLY），
// 分流順序必須 k8s 優先，不進帳號選擇器
const accountSelectorVisible = ref(false)
const pendingAccountAsset = ref(null)
const pendingAccounts = ref([])
// 選擇器是全域單例，開哪一種分頁的意圖必須跟著 pending 槽位一起保存
const pendingAccountKind = ref('terminal')
// latest-request-wins（專案慣例）**只套在選擇器的單一 pending 槽位**：
// 連點兩個多帳號資產時，先到者若補寫 pendingAccountAsset/pendingAccounts，
// 而 AccountSelector 僅在 modelValue false→true 才預選，就會拿 A 的帳號
// 對 B 發簽發。開籤本身不受此限——連開三個分頁是正常操作，不是競態
let accountSelectorSeq = 0

// 側欄整列 click：受存取狀態分化約束，鎖定／審核中一律不發簽發
function onAssetClick(asset) {
  if (entryState(asset) !== 'open') return
  openTab(asset)
}

// 主控台入口：與整列 click 同判準，帳號分流也走同一條路
function openConsoleTab(asset) {
  if (entryState(asset) !== 'open') return
  openTab(asset, 'console')
}

async function openTab(asset, kind = 'terminal') {
  if (asset.protocol === 'k8s') {
    pendingK8sAsset.value = asset
    podSelectorVisible.value = true
    return
  }
  pendingAccountKind.value = kind
  const seq = ++accountSelectorSeq
  let accounts = []
  try {
    const resp = await listAssetAccounts(asset.id, { skipErrorToast: true })
    accounts = resp.data || []
  } catch (err) {
    // 清單取用失敗不阻斷連線：帳號授權的強制點在後端（簽發／兌換兩處 DB 現查），
    // 此處只是「要不要打擾使用者」的呈現層判斷。但**不得靜默**——使用者有權知道
    // 自己是以預設帳號（通常是特權帳號）連上的，故明示後照常建線
    console.warn('[Workspace] 載入資產帳號失敗，改以預設帳號連線:', err)
    ElMessage.warning(t('accountSelector.fallbackDefault'))
    createTab(asset, null, null, false, kind)
    return
  }
  if (accounts.length > 1) {
    // 過期的請求不得覆寫已被更新的選擇器狀態
    if (seq !== accountSelectorSeq) return
    pendingAccountAsset.value = asset
    pendingAccounts.value = accounts
    accountSelectorVisible.value = true
    return
  }
  // 零帳號（原本即無憑證的資產）或單一有效帳號：直連不打擾
  createTab(asset, null, accounts[0] || null, false, kind)
}

// picked＝使用者實際在選擇器裡挑過帳號（僅影響分頁標題是否附 @帳號：
// migration 後幾乎每個資產都有 default account，無條件附加會讓所有標題
// 變成 `web-01@root`，反而稀釋了「這個分頁用的不是預設身分」的訊號）
function createTab(asset, k8s, account, picked = false, kind = 'terminal') {
  tabSeq += 1
  const key = `tab-${tabSeq}`
  // 同 pod 重複開：計序號以區分分頁
  let dupIdx = 0
  if (k8s && k8s.pod) {
    const same = tabs.value.filter(
      (t) => t.protocol === 'k8s' && t.assetId === asset.id && t.k8sPod === k8s.pod
    ).length
    if (same > 0) dupIdx = same + 1
  }
  tabs.value = [
    ...tabs.value,
    {
      key,
      assetId: asset.id,
      name: asset.name,
      protocol: asset.protocol,
      // 帳號快照（連線當下所選）：accountId 進 connect-token 簽發，
      // accountUsername 只供分頁標題辨識，不參與任何判定
      accountId: account ? account.id : null,
      accountUsername: account ? account.username : '',
      accountPicked: picked,
      fileVisible: false,
      snippetVisible: false,
      statsVisible: false,
      shareVisible: false,
      sessionId: null,
      status: 'connecting',
      k8sNamespace: asset.k8s_namespace || '',
      k8sPod: k8s ? k8s.pod : '',
      k8sContainer: k8s ? k8s.container : '',
      k8sMode: k8s ? k8s.mode : '',
      k8sDupIdx: dupIdx,
      // 分頁型別：'terminal'（xterm 載體）或 'console'（查詢主控台）
      kind,
      // 允許清單隨資產列一起帶進來——主控台靠它分辨「目標端沒有庫」
      // 與「清單與目標端無交集」兩種空樹
      allowedDatabases: [...(asset.allowed_databases || [])],
      // 主控台分頁狀態：編輯器文字、未收束的單位、上一場會話（重連時交還）
      sql: '',
      pendingEventId: '',
      pendingSql: '',
      previousSessionId: null,
      unsettled: false
    }
  ]
  activeKey.value = key
}

// 分頁標籤：K8s 顯示 pod（同資產多 pod 可區分）+ 日誌標記 + 重複序號；
// **使用者挑過帳號的**分頁顯示 `資產名@帳號`（同資產不同帳號可一眼分辨）；
// 單帳號直連沿用純資產名（「不打擾」語義的一致延伸）
function tabLabel(tab) {
  if (tab.protocol === 'k8s' && tab.k8sPod) {
    const pod = tab.k8sPod
    if (tab.k8sMode === 'logs') {
      return tab.k8sDupIdx
        ? t('workspace.k8sTabLogsDup', { pod, n: tab.k8sDupIdx })
        : t('workspace.k8sTabLogs', { pod })
    }
    return tab.k8sDupIdx ? `${pod} #${tab.k8sDupIdx}` : pod
  }
  return tab.accountPicked && tab.accountUsername
    ? `${tab.name}@${tab.accountUsername}`
    : tab.name
}

function onPodSelected(sel) {
  if (pendingK8sAsset.value) {
    createTab(pendingK8sAsset.value, sel)
    pendingK8sAsset.value = null
  }
}

function onAccountSelected(account) {
  if (pendingAccountAsset.value) {
    createTab(pendingAccountAsset.value, null, account, true, pendingAccountKind.value)
    pendingAccountAsset.value = null
    pendingAccounts.value = []
  }
}

// K8s 容器檔案上傳（kubectl cp）：傳到容器 /tmp
const k8sFileInput = ref(null)
function triggerK8sUpload() {
  if (k8sFileInput.value) k8sFileInput.value.click()
}
async function onK8sFileChange(e) {
  const file = e.target.files && e.target.files[0]
  const tab = activeTermTab.value
  if (!file || !tab) {
    e.target.value = ''
    return
  }
  // 讓使用者選目標目錄（預設 /tmp）；/tmp 非安全邊界，傳到哪都受容器權限與審計約束
  let destDir = '/tmp'
  try {
    const { value } = await ElMessageBox.prompt(
      t('workspace.uploadPrompt', { pod: tab.k8sPod, container: tab.k8sContainer }),
      t('workspace.uploadTitle', { name: file.name }),
      {
        inputValue: '/tmp',
        inputPattern: /^\/.+/,
        inputErrorMessage: t('workspace.absolutePathRequired'),
        confirmButtonText: t('workspace.uploadConfirm'),
        cancelButtonText: t('common.cancel')
      }
    )
    destDir = value
  } catch {
    e.target.value = ''
    return
  }
  const fd = new FormData()
  fd.append('pod', tab.k8sPod)
  fd.append('container', tab.k8sContainer)
  fd.append('dest_path', destDir)
  fd.append('file', file)
  try {
    const resp = await uploadK8sFile(tab.assetId, fd)
    ElMessage.success(t('workspace.uploaded', { path: resp.path, size: resp.size }))
  } catch (err) {
    ElMessage.error(
      resolveApiError(err.response?.data, err.response?.status, t('workspace.uploadFailed'))
    )
  } finally {
    e.target.value = ''
  }
}

// K8s 容器檔案下載（kubectl cp）：輸入容器內絕對路徑 → 取回瀏覽器下載
async function triggerK8sDownload() {
  const tab = activeTermTab.value
  if (!tab) return
  let path
  try {
    const { value } = await ElMessageBox.prompt(
      t('workspace.downloadPrompt', { pod: tab.k8sPod, container: tab.k8sContainer }),
      t('workspace.downloadTitle'),
      {
        inputPlaceholder: '/tmp/example.log',
        inputPattern: /^\/.+/,
        inputErrorMessage: t('workspace.absolutePathRequired'),
        confirmButtonText: t('workspace.downloadConfirm'),
        cancelButtonText: t('common.cancel')
      }
    )
    path = value
  } catch {
    return
  }
  try {
    const blob = await downloadK8sFile(tab.assetId, {
      pod: tab.k8sPod,
      container: tab.k8sContainer,
      path
    })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = path.split('/').pop() || 'download'
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
    ElMessage.success(t('workspace.downloaded', { name: a.download }))
  } catch (err) {
    // 下載失敗 body 是 Blob，解析回 JSON 取後端精準訊息（如「容器內找不到該檔案：…」）
    let msg = t('workspace.downloadFailed')
    const data = err?.response?.data
    if (data instanceof Blob) {
      try {
        const parsed = JSON.parse(await data.text())
        if (parsed?.error) msg = parsed.error
      } catch { /* 非 JSON：保留預設訊息 */ }
    }
    ElMessage.error(msg)
  }
}

function closeTab(key) {
  const index = tabs.value.findIndex((t) => t.key === key)
  if (index < 0) return
  const target = tabs.value[index]
  confirmClosing([target], () => {
    tabs.value = tabs.value.filter((t) => t.key !== key)

    // 關閉目前頁籤：切到鄰近頁籤
    if (activeKey.value === key && tabs.value.length) {
      const next = tabs.value[Math.min(index, tabs.value.length - 1)]
      activeKey.value = next.key
    }
  })
}

// 未收束的單位存回分頁狀態：面板 remount（重連）後要靠它回頭問結果
function onConsolePending(tab, payload) {
  tab.pendingEventId = payload?.eventId || ''
  tab.pendingSql = payload?.sql || ''
}

// 斷線/錯誤的籤標灰但保留：頁內重連，不自動關籤——自動關籤會一併帶走重連入口與錯誤訊息
function isDisconnected(tab) {
  return tab.status === 'closed' || tab.status === 'error'
}

function toggleSidebar() {
  sidebarCollapsed.value = !sidebarCollapsed.value
  localStorage.setItem(SIDEBAR_COLLAPSED_KEY, sidebarCollapsed.value ? '1' : '0')
}

function openSystem() {
  window.open('/', '_blank')
}

// 測試掛點：頁籤邏輯不依賴 DOM 互動即可驅動
defineExpose({ openTab, openConsoleTab, closeTab, tabs, activeKey, entryState })
</script>

<style scoped>
.workspace {
  display: flex;
  flex-direction: column;
  height: 100vh;
  background: var(--ot-terminal-bg);
  overflow: hidden;
}

.workspace-header {
  display: flex;
  align-items: center;
  gap: 10px;
  height: 40px;
  padding: 0 10px;
  flex-shrink: 0;
  background: var(--ot-bg-elevated);
  border-bottom: 1px solid var(--ot-border);
}

.header-icon {
  color: var(--ot-terminal-fg);
}

.brand-link {
  font-weight: 600;
  color: var(--ot-terminal-fg);
}

.workspace-hint {
  font-size: 12px;
  opacity: 0.6;
  color: var(--ot-terminal-fg);
}

.workspace-lang {
  margin-left: auto;
}

.workspace-lang-label {
  cursor: pointer;
  font-size: 12px;
  color: var(--ot-terminal-fg);
  opacity: 0.7;
}

.workspace-lang-label:hover {
  opacity: 1;
  color: var(--ot-primary);
}

.workspace-body {
  display: flex;
  flex: 1;
  /* flex 子項預設 min-height:auto 會被內容撐破：必須歸零才能正確收斂於視口 */
  min-height: 0;
  overflow: hidden;
}

.workspace-sidebar {
  display: flex;
  flex-direction: column;
  gap: 8px;
  /* 名稱、狀態圖示、主控台入口、協議 chip 四段共用同一列；
     220 px 在日文下連 6 個字元的資產名都留不住 */
  width: 240px;
  flex-shrink: 0;
  padding: 10px;
  background: var(--ot-bg-surface);
  border-right: 1px solid var(--ot-border);
}

.asset-list {
  flex: 1;
  overflow-y: auto;
}

.asset-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
  padding: 7px 8px;
  border-radius: 6px;
  cursor: pointer;
  color: var(--ot-terminal-fg);
}

.asset-item:hover {
  background: var(--ot-bg-hover);
}

.asset-item-name {
  flex: 1;
  min-width: 0;
  font-size: 13px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* 需申請／審核中：整列不是連線入口，游標不得暗示可點 */
.asset-item.is-gated {
  cursor: default;
  opacity: 0.7;
}

.asset-item-gate {
  flex-shrink: 0;
  font-size: 13px;
  color: var(--el-text-color-secondary);
}

.asset-item-console {
  flex-shrink: 0;
  display: inline-flex;
  font-size: 13px;
}

/* 分頁型別圖示：與標題同列，不佔第二行 */
.tab-kind-icon {
  margin-right: 4px;
  vertical-align: -2px;
}

.asset-empty {
  padding: 12px;
  font-size: 12px;
  opacity: 0.6;
  color: var(--ot-terminal-fg);
}

.workspace-tabs {
  display: flex;
  flex-direction: column;
  flex: 1;
  min-width: 0;
  position: relative;
}

/* 只用 el-tabs 的頁籤列，內容由 tab-panels 承載 */
.workspace-tabs :deep(.el-tabs__content) {
  display: none;
}

.workspace-tabs :deep(.el-tabs--border-card) {
  background: var(--ot-bg-elevated);
  border: none;
}

.tab-panels {
  position: relative;
  flex: 1;
  min-height: 0;
}

.tab-panel {
  position: absolute;
  inset: 0;
}

/* K8s 連線 context（頂部工具列，顯示目前 ns/pod/container/模態）*/
.k8s-ctx {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  margin-right: 12px;
  font-size: 12px;
  font-family: 'IBM Plex Mono', ui-monospace, monospace;
  color: var(--el-text-color-regular);
  white-space: nowrap;
}
.k8s-ctx__seg b {
  color: var(--el-text-color-secondary);
  font-weight: 600;
  margin-right: 3px;
}
.k8s-ctx__badge {
  padding: 1px 7px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
}
.k8s-ctx__badge.is-exec {
  color: #60a5fa;
  background: rgba(59, 130, 246, 0.15);
}
.k8s-ctx__badge.is-logs {
  color: #34d399;
  background: rgba(52, 211, 153, 0.15);
}

.tabbar-tools {
  position: absolute;
  top: 0;
  right: 8px;
  height: 40px;
  display: flex;
  align-items: center;
  gap: 4px;
  z-index: 5;
}

.tool-btn {
  border: none;
  background: transparent;
  color: var(--el-text-color-secondary);
  cursor: pointer;
  font-size: 15px;
  padding: 5px;
  border-radius: var(--el-border-radius-base);
  display: flex;
  align-items: center;
}

.tool-btn:hover {
  color: var(--el-color-primary);
  background: var(--el-fill-color);
}

.tab-context-menu {
  position: fixed;
  z-index: 3000;
  min-width: 120px;
  margin: 0;
  padding: 4px 0;
  list-style: none;
  background: var(--el-bg-color-overlay);
  border: 1px solid var(--el-border-color);
  border-radius: 4px;
  box-shadow: var(--el-box-shadow-light);
  font-size: 13px;
}

.tab-context-menu li {
  padding: 6px 16px;
  cursor: pointer;
  color: var(--el-text-color-primary);
}

.tab-context-menu li:hover {
  background: var(--el-fill-color-light);
}

.tab-context-menu .menu-divider {
  height: 1px;
  margin: 4px 0;
  padding: 0;
  background: var(--el-border-color-lighter);
  cursor: default;
}

.tab-disconnected {
  color: var(--ot-text-disabled);
}

.tabs-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
}

.asset-group-label {
  padding: 8px 4px 4px;
  font-size: 11px;
  font-weight: 600;
  color: var(--el-text-color-secondary);
  text-transform: uppercase;
}
</style>
