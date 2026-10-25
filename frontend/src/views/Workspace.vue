<template>
  <div
    class="workspace"
    :class="{ 'is-resizing': resizing }"
  >
    <WorkspaceHeader
      :collapsed="sidebarCollapsed"
      @toggle-sidebar="toggleSidebar"
    />

    <div class="workspace-body">
      <!-- 可收合資產側欄：列表、搜尋、存取狀態說明與拖寬都在元件內 -->
      <WorkspaceAssetSidebar
        v-show="!sidebarCollapsed"
        ref="sidebarRef"
        :selected-asset-id="selectedAssetId"
        @open-asset="(asset) => openTab(asset)"
        @open-console="(asset) => openTab(asset, 'console')"
        @resizing="resizing = $event"
      />

      <!-- 會話頁籤區 -->
      <div
        class="workspace-tabs"
        :style="{ '--tabbar-tools-width': tabbarReserve + 'px' }"
      >
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
              <!-- 標題有最大寬度、單行省略；停留時給完整標題（含手選帳號） -->
              <el-tooltip
                :content="tabTitleTip(tab)"
                placement="bottom"
                :enterable="false"
                :show-after="300"
              >
                <span
                  class="tab-label"
                  :class="{ 'tab-disconnected': isDisconnected(tab) }"
                  @contextmenu.prevent="openTabMenu($event, tab.key)"
                >
                  <!-- 同一個資產可同時開命令列與主控台，標題文字相同：
                       分頁型別要靠圖示分辨 -->
                  <el-icon
                    class="tab-kind-icon"
                    role="img"
                    :aria-label="tab.kind === 'console' ? $t('workspace.consoleTabTip') : protocolFullName(tab.protocol)"
                  >
                    <component :is="tabIcon(tab)" />
                  </el-icon>
                  <span
                    class="tab-title"
                    data-test="tab-title"
                  >{{ tabDisplayLabel(tab) }}</span>
                </span>
              </el-tooltip>
            </template>
          </el-tab-pane>
        </el-tabs>

        <!-- 會話工具：置於頁籤列右端既有空白，操作目前啟用文字終端會話 -->
        <WorkspaceTabTools
          v-if="activeTermTab"
          :tab="activeTermTab"
          @open-panel="openTabPanel"
          @width="tabbarToolsWidth = $event"
        />

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
            <el-empty :description="canViewAssets ? $t('workspace.emptyTabs') : $t('workspace.emptyTabsNoAssetView')" />
          </div>
        </div>
      </div>
    </div>

    <!-- 頁籤右鍵選單 -->
    <WorkspaceTabMenu
      v-if="tabMenu.visible"
      :x="tabMenu.x"
      :y="tabMenu.y"
      @select="onTabMenuSelect"
    />

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
import { t } from '@/i18n'
// 分頁型別圖示取 lucide-vue-next，維持全站 icon 體系一致
import { Database, SquareTerminal, Monitor, Container } from 'lucide-vue-next'
import { ElMessage } from 'element-plus'
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
import WorkspaceAssetSidebar from '@/components/workspace/WorkspaceAssetSidebar.vue'
import WorkspaceHeader from '@/components/workspace/WorkspaceHeader.vue'
import WorkspaceTabTools from '@/components/workspace/WorkspaceTabTools.vue'
import WorkspaceTabMenu from '@/components/workspace/WorkspaceTabMenu.vue'
import { readStorage, writeStorage } from '@/components/workspace/storage'
import { getAsset } from '@/api/assets'
import { can, useCapabilities } from '@/composables/useCapabilities'
import { listAssetAccounts } from '@/api/assetAccounts'
import { moveItem } from '@/utils/move-item'
import { isTextTerminal, protocolIconKind, protocolFullName } from '@/utils/protocol'
import { closeOthers, closeLeft, closeRight, closeAll } from '@/utils/tab-close'
import { confirmDestructive } from '@/utils/confirm'

// 沒有資產檢視權限時側欄不列資產，右側主區的空態文案跟著改
const { ready: capsReady } = useCapabilities()
const canViewAssets = computed(() => can('asset:view') || !capsReady.value)

const SIDEBAR_COLLAPSED_KEY = 'workspace-sidebar-collapsed'

const PROTOCOL_ICONS = { terminal: SquareTerminal, desktop: Monitor, database: Database, container: Container }

const route = useRoute()

const sidebarRef = ref(null)
const sidebarCollapsed = ref(readStorage(SIDEBAR_COLLAPSED_KEY) === '1')
// 側欄拖寬中：整個工作區鎖游標與文字選取
const resizing = ref(false)

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

// 目前啟用分頁的資產＝側欄選中列
const selectedAssetId = computed(() => tabs.value.find((t) => t.key === activeKey.value)?.assetId ?? null)

// 側欄的存取狀態判準與說明框都在側欄元件內；這裡只轉接
const entryState = (asset) => sidebarRef.value?.entryState(asset)
const loadAssets = () => sidebarRef.value?.loadAssets()

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

// 側欄說明框的 Esc／點外關閉由側欄元件自行處理
function onGlobalKeydown(e) {
  if (e.key === 'Escape') hideTabMenu()
}

function onDocumentClick() {
  hideTabMenu()
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

const TAB_MENU_ACTIONS = {
  reconnect: menuReconnect,
  duplicate: menuDuplicate,
  close: menuClose,
  closeOthers: menuCloseOthers,
  closeLeft: menuCloseLeft,
  closeRight: menuCloseRight,
  closeAll: menuCloseAll,
}

function onTabMenuSelect(command) {
  TAB_MENU_ACTIONS[command]?.()
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
  document.removeEventListener('click', onDocumentClick)
  document.removeEventListener('keydown', onGlobalKeydown)
})

onMounted(async () => {
  document.addEventListener('click', onDocumentClick)
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

// 側欄整列 click 與主控台入口：同一組存取狀態判準在側欄元件內，
// 受限狀態只出說明、不發簽發；可連線時側欄回拋 open-asset／open-console
function onAssetClick(asset, event) {
  sidebarRef.value?.activate(asset, 'terminal', event)
}

function openConsoleTab(asset, event) {
  sidebarRef.value?.activate(asset, 'console', event)
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

// 分頁列顯示的標題（斷線時附標記）；寬度由 CSS 限制，超出單行省略
function tabDisplayLabel(tab) {
  const label = tabLabel(tab)
  return isDisconnected(tab) ? t('workspace.tabDisconnected', { label }) : label
}

// 停留提示：完整標題，主控台分頁另註明型別
function tabTitleTip(tab) {
  const label = tabDisplayLabel(tab)
  return tab.kind === 'console' ? t('workspace.tabTitleConsole', { label }) : label
}

// 分頁型別圖示：主控台＝資料庫；命令列類（含資料庫 CLI）＝終端；k8s＝容器；圖形＝桌面
function tabIcon(tab) {
  if (tab.kind === 'console') return Database
  const kind = protocolIconKind(tab.protocol)
  return kind === 'database' ? SquareTerminal : PROTOCOL_ICONS[kind]
}

// 分頁列右側預留工具列寬度：工具列回報實測寬度寫入 CSS 變數，分頁不再被它蓋住
const tabbarToolsWidth = ref(0)
// 工具列距右緣 8px，另留 8px 間隔
const TABBAR_TOOLS_GAP = 16
const tabbarReserve = computed(() =>
  (activeTermTab.value && tabbarToolsWidth.value > 0 ? tabbarToolsWidth.value + TABBAR_TOOLS_GAP : 0)
)

// 工具列按鈕打開目前分頁的對應面板（分享／檔案／指標／片段）
function openTabPanel(panel) {
  const tab = activeTermTab.value
  if (tab) tab[`${panel}Visible`] = true
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
  writeStorage(SIDEBAR_COLLAPSED_KEY, sidebarCollapsed.value ? '1' : '0')
}

// 測試掛點：頁籤邏輯不依賴 DOM 互動即可驅動
defineExpose({ openTab, onAssetClick, openConsoleTab, closeTab, tabs, activeKey, entryState, loadAssets })
</script>

<style scoped>
.workspace {
  display: flex;
  flex-direction: column;
  height: 100vh;
  background: var(--ot-terminal-bg);
  overflow: hidden;
}

.workspace-body {
  display: flex;
  flex: 1;
  /* flex 子項預設 min-height:auto 會被內容撐破：必須歸零才能正確收斂於視口 */
  min-height: 0;
  overflow: hidden;
}

.workspace.is-resizing {
  cursor: col-resize;
  user-select: none;
}

/* 分頁標題：圖示＋最大寬度 220px 的單行省略 */
.tab-label {
  display: inline-flex;
  align-items: center;
  max-width: 244px;
}

.tab-kind-icon {
  flex-shrink: 0;
  margin-right: 4px;
}

.tab-title {
  display: inline-block;
  max-width: 220px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
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

/* 分頁列右側預留工具列的實測寬度（--tabbar-tools-width），分頁捲動區不延伸到工具列下方 */
.workspace-tabs :deep(.el-tabs__header) {
  padding-right: var(--tabbar-tools-width, 0px);
}

.tab-panels {
  position: relative;
  flex: 1;
  min-height: 0;
}

.tab-panel {
  position: absolute;
  /* 三類連線畫面與主區四邊一致的留白；不加在畫面元件內距，避免疊成兩層 */
  inset: 6px;
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
</style>
