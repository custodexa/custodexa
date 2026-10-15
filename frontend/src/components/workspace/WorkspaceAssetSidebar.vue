<template>
  <!-- 可收合資產側欄：搜尋、重新整理、分組樹、存取狀態說明、拖寬把手 -->
  <div
    class="workspace-sidebar"
    :style="{ width: sidebarWidth + 'px' }"
  >
    <div class="sidebar-search">
      <el-input
        v-model="assetFilter"
        size="small"
        :placeholder="$t('workspace.searchAssets')"
        :prefix-icon="Search"
        clearable
      />
      <!-- 重新整理只換列表資料，不碰分頁陣列與各分頁元件（連線不中斷） -->
      <el-tooltip
        :content="loadingAssets ? $t('workspace.refreshing') : $t('workspace.refreshList')"
        placement="right"
        :enterable="false"
      >
        <button
          type="button"
          class="sidebar-refresh"
          :class="{ 'is-loading': loadingAssets }"
          :disabled="loadingAssets"
          :aria-label="$t('workspace.refreshList')"
          :aria-busy="loadingAssets ? 'true' : 'false'"
          data-test="refresh-assets"
          @click="loadAssets"
        >
          <el-icon><RefreshCw /></el-icon>
        </button>
      </el-tooltip>
    </div>
    <div
      v-for="notice in listNotices"
      :key="notice"
      class="asset-list-notice"
      role="status"
      data-test="list-notice"
    >
      {{ notice }}
    </div>
    <div class="asset-list">
      <template
        v-for="row in sidebarRows"
        :key="row.rowKey"
      >
        <!-- 分組節點：台數緊跟節點名，只截節點名 -->
        <div
          v-if="row.type === 'node'"
          class="asset-node"
          :style="{ paddingLeft: nodeIndent(row.depth) + 'px' }"
          role="button"
          tabindex="0"
          :aria-expanded="isNodeExpanded(row.node.key) ? 'true' : 'false'"
          :aria-label="$t('workspace.nodeToggle', { name: row.node.name })"
          :data-node-key="row.node.key"
          data-test="asset-node"
          @click="toggleNode(row.node.key)"
          @keydown.enter.space.prevent="toggleNode(row.node.key)"
        >
          <el-icon class="asset-node-chevron">
            <ChevronDown v-if="isNodeExpanded(row.node.key)" />
            <ChevronRight v-else />
          </el-icon>
          <span class="asset-node-name">{{ row.node.name }}</span>
          <span
            class="asset-node-count"
            data-test="node-count"
          >{{ row.node.count }}</span>
        </div>
        <WorkspaceAssetRow
          v-else
          :asset="row.asset"
          :row-key="row.rowKey"
          :depth="row.depth"
          :label="assetLabel(row)"
          :state="entryState(row.asset)"
          :gated="isBlocked(row.asset)"
          :selected="isSelectedAsset(row.asset)"
          :tip-disabled="!!explain"
          :search-term="assetFilter.trim()"
          :name-ref="nameRef(row.rowKey)"
          @activate="(asset, e) => activate(asset, 'terminal', e)"
          @console="(asset, e) => activate(asset, 'console', e)"
        />
      </template>
      <div
        v-if="!sidebarRows.length"
        class="asset-empty"
      >
        {{ $t('workspace.noMatchingAssets') }}
      </div>
    </div>
    <!-- 拖曳把手：寬度 200–480，放開時記住；鍵盤左右鍵每次 16px -->
    <div
      class="sidebar-resizer"
      :class="{ 'is-active': resizing }"
      role="slider"
      aria-orientation="horizontal"
      :aria-valuenow="sidebarWidth"
      :aria-valuemin="SIDEBAR_MIN_WIDTH"
      :aria-valuemax="SIDEBAR_MAX_WIDTH"
      :aria-valuetext="sidebarWidth + 'px'"
      :aria-label="$t('workspace.sidebarResize')"
      tabindex="0"
      data-test="sidebar-resizer"
      @pointerdown="onResizeStart"
      @keydown="onResizeKey"
    >
      <span class="sidebar-resizer__grip">
        <el-icon><EllipsisVertical /></el-icon>
      </span>
      <span
        v-if="resizing"
        class="sidebar-resizer__badge"
      >{{ sidebarWidth }}px</span>
    </div>

    <WorkspaceAccessExplain
      v-if="explain"
      ref="explainRef"
      :state="explain.state"
      :top="explain.top"
      :left="explain.left"
      @close="closeExplain(true)"
      @apply="goApply(explain.asset)"
    />
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onBeforeUnmount, watch, nextTick } from 'vue'
import { RefreshCw, ChevronDown, ChevronRight, EllipsisVertical, Search } from 'lucide-vue-next'
import { t } from '@/i18n'
import { getAssetList } from '@/api/assets'
import { assetEntryState, BLOCKED_ENTRY_STATES } from '@/utils/asset-access'
import { buildAssetTree, flattenTree, flatRows, rootKeys } from '@/utils/asset-tree'
import { useRoles } from '@/composables/useRoles'
import WorkspaceAssetRow from './WorkspaceAssetRow.vue'
import WorkspaceAccessExplain from './WorkspaceAccessExplain.vue'
import { readStorage, writeStorage } from './storage'
import { useAssetNameFit } from './useAssetNameFit'

const props = defineProps({
  // 目前啟用分頁的資產 id（選中列）
  selectedAssetId: { type: [Number, String], default: null },
})

// open-asset／open-console 只在可連線的狀態發出（受限狀態由本元件就地說明）；
// resizing 為拖曳中狀態，供外層鎖游標與選取
const emit = defineEmits(['open-asset', 'open-console', 'resizing'])

const SIDEBAR_WIDTH_KEY = 'custodexa.workspace.sidebarWidth'
const EXPANDED_NODES_KEY = 'custodexa.workspace.expandedNodes'
const SIDEBAR_MIN_WIDTH = 200
const SIDEBAR_MAX_WIDTH = 480
const SIDEBAR_DEFAULT_WIDTH = 280
const SIDEBAR_KEY_STEP = 16
const ASSET_PAGE_SIZE = 100
// 翻頁安全上限：伺服端 total 異常時不無限抓下去
const MAX_ASSET_PAGES = 200

const clampSidebarWidth = (w) => Math.min(SIDEBAR_MAX_WIDTH, Math.max(SIDEBAR_MIN_WIDTH, Math.round(w)))

function loadSidebarWidth() {
  const raw = readStorage(SIDEBAR_WIDTH_KEY)
  if (raw === null || raw === '') return SIDEBAR_DEFAULT_WIDTH
  const n = Number(raw)
  return Number.isFinite(n) && n >= SIDEBAR_MIN_WIDTH && n <= SIDEBAR_MAX_WIDTH
    ? Math.round(n)
    : SIDEBAR_DEFAULT_WIDTH
}

// null＝沒有保存紀錄（首次：預設展開第一層）
function loadExpandedNodes() {
  const raw = readStorage(EXPANDED_NODES_KEY)
  if (!raw) return null
  try {
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? new Set(parsed.filter((k) => typeof k === 'string')) : null
  } catch {
    return null
  }
}

const assets = ref([])
const assetFilter = ref('')
const sidebarWidth = ref(loadSidebarWidth())

// 存取狀態分化：命令列與主控台兩個入口共用同一判準，不單做一邊
const { isPrivileged } = useRoles()
const entryState = (asset) => assetEntryState(asset, { isPrivileged: isPrivileged.value })
const isBlocked = (asset) => BLOCKED_ENTRY_STATES.includes(entryState(asset))

// ---- 分組樹與搜尋 ----

const searchTerm = computed(() => assetFilter.value.trim().toLowerCase())

// 搜尋比對名稱、主機位址、節點路徑；只因路徑命中時該節點下全部資產顯示
const matchesSearch = (asset, pathText) => {
  const term = searchTerm.value
  return [asset?.name, asset?.host, pathText].some((v) => String(v ?? '').toLowerCase().includes(term))
}

const assetTree = computed(() =>
  buildAssetTree(assets.value, {
    ungroupedLabel: t('assets.ungrouped'),
    match: searchTerm.value ? matchesSearch : null,
  })
)

const savedExpanded = ref(loadExpandedNodes())

// 使用者保存的展開狀態；無紀錄時預設展開第一層
const baseExpanded = computed(() =>
  savedExpanded.value || new Set(rootKeys(buildAssetTree(assets.value, { ungroupedLabel: t('assets.ungrouped') }).nodes))
)

// 有關鍵字時命中節點一律暫時展開（不覆寫保存的狀態；清空即回到保存的狀態）
const isNodeExpanded = (key) => (searchTerm.value ? true : baseExpanded.value.has(key))

function toggleNode(key) {
  if (searchTerm.value) return
  const next = new Set(baseExpanded.value)
  if (next.has(key)) next.delete(key)
  else next.add(key)
  savedExpanded.value = next
  writeStorage(EXPANDED_NODES_KEY, JSON.stringify([...next]))
}

const sidebarRows = computed(() => {
  const { nodes, flat } = assetTree.value
  return flat ? flatRows(nodes) : flattenTree(nodes, isNodeExpanded)
})

const nodeIndent = (depth) => 4 + depth * 14

// 選中列：目前分頁的資產，或說明框所指的列（主控台鈕常駐顯示）
const isSelectedAsset = (asset) =>
  asset.id === props.selectedAssetId || asset.id === explain.value?.asset?.id

// ---- 名稱截斷 ----

const { nameRef, assetLabel, dispose: disposeNameFit } = useAssetNameFit()

// ---- 側欄寬度拖曳 ----

const resizing = ref(false)
let dragStartX = 0
let dragStartWidth = 0

watch(resizing, (v) => emit('resizing', v))

function saveSidebarWidth() {
  writeStorage(SIDEBAR_WIDTH_KEY, String(sidebarWidth.value))
}

function onResizeMove(e) {
  sidebarWidth.value = clampSidebarWidth(dragStartWidth + (e.clientX - dragStartX))
}

function stopResizeListeners() {
  window.removeEventListener('pointermove', onResizeMove)
  window.removeEventListener('pointerup', onResizeEnd)
  window.removeEventListener('pointercancel', onResizeEnd)
}

function onResizeEnd() {
  stopResizeListeners()
  if (!resizing.value) return
  resizing.value = false
  saveSidebarWidth()
}

function onResizeStart(e) {
  if (typeof e.button === 'number' && e.button !== 0) return
  e.preventDefault()
  resizing.value = true
  dragStartX = e.clientX
  dragStartWidth = sidebarWidth.value
  window.addEventListener('pointermove', onResizeMove)
  window.addEventListener('pointerup', onResizeEnd)
  window.addEventListener('pointercancel', onResizeEnd)
}

function onResizeKey(e) {
  const delta = { ArrowLeft: -SIDEBAR_KEY_STEP, ArrowRight: SIDEBAR_KEY_STEP }[e.key]
  if (delta === undefined) return
  e.preventDefault()
  sidebarWidth.value = clampSidebarWidth(sidebarWidth.value + delta)
  saveSidebarWidth()
}

// ---- 受限資產的點擊說明 ----

const explain = ref(null)
const explainRef = ref(null)
const EXPLAIN_WIDTH = 300
const EXPLAIN_MAX_HEIGHT = 180

function showExplain(asset, state, event) {
  const row = event?.currentTarget?.closest?.('.asset-item') || event?.target?.closest?.('.asset-item') || null
  const rect = row?.getBoundingClientRect?.()
  const vw = window.innerWidth || 1280
  const vh = window.innerHeight || 800
  const left = rect ? Math.min(rect.right + 8, vw - EXPLAIN_WIDTH - 8) : sidebarWidth.value + 8
  const top = rect ? Math.max(8, Math.min(rect.top - 4, vh - EXPLAIN_MAX_HEIGHT - 8)) : 80
  explain.value = { asset, state, top, left, anchor: row }
  nextTick(() => explainRef.value?.focus?.())
}

function closeExplain(restoreFocus = false) {
  const anchor = explain.value?.anchor
  explain.value = null
  if (restoreFocus) anchor?.focus?.()
}

// 「前往資產頁申請」：新瀏覽器分頁開資產頁並自動開該資產的申請表單，工作區分頁不受影響
function goApply(asset) {
  window.open(`/assets?apply=${asset.id}`, '_blank')
  closeExplain()
}

// 整列與主控台鈕共用：僅檢視／審核中／需審核不發簽發，改給說明（不再點了沒反應）；
// 需填理由照常開分頁，由分頁元件的簽發流程就地要求填理由
function activate(asset, kind = 'terminal', event) {
  const state = entryState(asset)
  if (BLOCKED_ENTRY_STATES.includes(state)) {
    showExplain(asset, state, event)
    return
  }
  closeExplain()
  emit(kind === 'console' ? 'open-console' : 'open-asset', asset)
}

// 點說明框以外任一處即關閉；點說明框本身、或點開它的那一列除外（那一下正是開啟動作）
function onDocumentClick(e) {
  if (!explain.value) return
  if (explainRef.value?.contains?.(e.target)) return
  if (explain.value.anchor?.contains?.(e.target)) return
  closeExplain()
}

function onDocumentKeydown(e) {
  if (e.key === 'Escape' && explain.value) closeExplain(true)
}

// ---- 列表載入：逐頁取完，重新整理只換列表 ----

const loadingAssets = ref(false)
const listIncomplete = ref(false)
const refreshFailed = ref(false)
let loadSeq = 0

const listNotices = computed(() => [
  ...(refreshFailed.value ? [t('workspace.refreshFailed')] : []),
  ...(listIncomplete.value ? [t('workspace.listIncomplete')] : []),
])

async function fetchAllAssets() {
  const byId = new Map()
  let fetched = 0
  for (let page = 1; page <= MAX_ASSET_PAGES; page++) {
    const resp = await getAssetList({ page, page_size: ASSET_PAGE_SIZE })
    const data = Array.isArray(resp?.data) ? resp.data : []
    // 翻頁期間有新增時同一筆可能跨頁重複：以 id 去重
    for (const a of data) if (!byId.has(a.id)) byId.set(a.id, a)
    fetched += data.length
    const total = Number(resp?.total)
    const done = !data.length || (Number.isFinite(total) ? fetched >= total : data.length < ASSET_PAGE_SIZE)
    if (done) return { list: [...byId.values()], complete: true }
  }
  return { list: [...byId.values()], complete: false }
}

// 只替換列表資料：分頁持有的是開籤當下的資產複本，重抓不會重建任何分頁
async function loadAssets() {
  const seq = ++loadSeq
  loadingAssets.value = true
  try {
    const { list, complete } = await fetchAllAssets()
    if (seq !== loadSeq) return
    assets.value = list.filter((a) => a.active !== false)
    listIncomplete.value = !complete
    refreshFailed.value = false
  } catch (err) {
    if (seq !== loadSeq) return
    // 失敗保留舊列表，於側欄明示目前內容是上次載入的
    console.error('[Workspace] 載入資產列表失敗:', err)
    refreshFailed.value = true
  } finally {
    if (seq === loadSeq) loadingAssets.value = false
  }
}

onMounted(() => {
  document.addEventListener('click', onDocumentClick)
  document.addEventListener('keydown', onDocumentKeydown)
})

onBeforeUnmount(() => {
  document.removeEventListener('click', onDocumentClick)
  document.removeEventListener('keydown', onDocumentKeydown)
  stopResizeListeners()
  disposeNameFit()
})

// 列表首次載入由外層在掛載時呼叫 loadAssets（與網址指定資產的開啟順序一致）
defineExpose({ loadAssets, activate, closeExplain, entryState, assets })
</script>

<style scoped>
.workspace-sidebar {
  position: relative;
  display: flex;
  flex-direction: column;
  gap: 8px;
  /* 寬度由使用者拖曳決定（200–480，預設 280），見 sidebarWidth */
  flex-shrink: 0;
  padding: 10px;
  background: var(--ot-bg-surface);
  border-right: 1px solid var(--ot-border);
}

.sidebar-search {
  display: flex;
  align-items: center;
  gap: 6px;
}

.sidebar-refresh {
  flex-shrink: 0;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 24px;
  padding: 0;
  border: 1px solid var(--ot-border);
  border-radius: var(--ot-radius-sm);
  background: transparent;
  color: var(--ot-text-secondary);
  cursor: pointer;
  font-size: 14px;
}

.sidebar-refresh:hover:not(:disabled),
.sidebar-refresh:focus-visible {
  color: var(--ot-primary);
  border-color: var(--ot-primary);
}

.sidebar-refresh:disabled {
  cursor: progress;
}

.sidebar-refresh.is-loading {
  color: var(--ot-primary);
  border-color: var(--ot-primary);
}

.sidebar-refresh.is-loading .el-icon {
  animation: sidebar-refresh-spin 0.9s linear infinite;
}

@keyframes sidebar-refresh-spin {
  to { transform: rotate(360deg); }
}

.asset-list-notice {
  padding: 6px 8px;
  font-size: 12px;
  line-height: 1.5;
  color: var(--ot-warning);
  border: 1px solid var(--ot-border);
  border-radius: var(--ot-radius-sm);
}

.asset-list {
  flex: 1;
  min-height: 0;
  overflow-y: auto;
}

/* 分組節點：節點名單行省略，台數不截 */
.asset-node {
  display: flex;
  align-items: center;
  gap: 4px;
  height: 28px;
  padding-right: 8px;
  border-radius: var(--ot-radius-sm);
  cursor: pointer;
  color: var(--ot-text-secondary);
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.02em;
}

.asset-node:hover {
  background: var(--ot-bg-hover);
}

.asset-node:focus-visible {
  outline: 2px solid var(--ot-primary);
  outline-offset: -2px;
}

.asset-node-chevron {
  flex-shrink: 0;
  font-size: 12px;
}

.asset-node-name {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.asset-node-count {
  flex-shrink: 0;
  font-weight: 400;
  color: var(--ot-text-disabled);
}

.asset-empty {
  padding: 12px;
  font-size: 12px;
  opacity: 0.6;
  color: var(--ot-terminal-fg);
}

/* 拖曳把手：側欄右緣整條可拖，中段顯示握把 */
.sidebar-resizer {
  position: absolute;
  top: 0;
  right: -4px;
  bottom: 0;
  width: 8px;
  z-index: 6;
  cursor: col-resize;
  display: flex;
  align-items: center;
  justify-content: center;
}

.sidebar-resizer::after {
  content: '';
  position: absolute;
  top: 0;
  bottom: 0;
  left: 3px;
  width: 2px;
  background: transparent;
}

.sidebar-resizer:hover::after,
.sidebar-resizer:focus-visible::after,
.sidebar-resizer.is-active::after {
  background: var(--ot-primary);
}

.sidebar-resizer:focus-visible {
  outline: none;
}

.sidebar-resizer__grip {
  position: relative;
  z-index: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 12px;
  height: 28px;
  border: 1px solid var(--ot-border);
  border-radius: var(--ot-radius-sm);
  background: var(--ot-bg-elevated);
  color: var(--ot-text-secondary);
  font-size: 12px;
}

.sidebar-resizer.is-active .sidebar-resizer__grip,
.sidebar-resizer:focus-visible .sidebar-resizer__grip {
  border-color: var(--ot-primary);
  color: var(--ot-primary);
}

.sidebar-resizer__badge {
  position: absolute;
  top: 50%;
  right: 12px;
  transform: translateY(24px);
  padding: 1px 6px;
  border-radius: var(--ot-radius-sm);
  background: var(--ot-primary);
  color: var(--ot-text-inverse);
  font-size: 12px;
  font-weight: 600;
  white-space: nowrap;
}
</style>
