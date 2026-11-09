<template>
  <el-drawer
    :model-value="modelValue"
    size="760px"
    class="inventory-drawer"
    destroy-on-close
    @update:model-value="(v) => emit('update:modelValue', v)"
    @close="stopPolling"
  >
    <template #header>
      <div class="inv-title">
        <h2>{{ $t('hostInventory.title') }}</h2>
        <span
          v-if="asset"
          class="inv-subtitle"
          data-test="inv-subtitle"
        >{{ $t('hostInventory.subtitle', { name: asset.name, host: asset.host }) }}</span>
      </div>
    </template>

    <div
      v-if="phase === 'loading'"
      class="inv-skeleton"
      data-test="inv-loading"
    >
      <el-skeleton
        :rows="5"
        animated
      />
    </div>
    <EmptyState
      v-else-if="phase === 'forbidden'"
      data-test="inv-forbidden"
      :title="$t('hostInventory.err.noViewScope')"
    />
    <EmptyState
      v-else-if="phase === 'notfound'"
      data-test="inv-notfound"
      :title="$t('hostInventory.err.notFound')"
    />
    <div
      v-else-if="phase === 'error'"
      class="inv-load-error"
      data-test="inv-load-error"
    >
      <span>{{ $t('hostInventory.err.readFailed') }}</span>
      <el-button
        size="small"
        data-test="inv-load-retry"
        @click="init"
      >
        {{ $t('hostInventory.btn.retry') }}
      </el-button>
    </div>

    <template v-else>
      <ReadonlyNote
        v-if="!canDiscover"
        class="inv-readonly"
        data-test="inv-readonly"
      >
        {{ $t('hostInventory.readonlyNote') }}
      </ReadonlyNote>

      <HostInventoryStatusCard
        :scan="scan"
        :default-name="defaultName"
        :start-message="startMessage"
        :start-message-go-accounts="startMessageGoAccounts"
        :start-message-go-executor="startMessageGoExecutor && identity.canExecutor.value"
        :blocked-reason="canDiscover ? startBlockedReason : ''"
        :blocked-go-accounts="noIdentity && supported && canEditAsset"
        :can-edit-asset="canEditAsset"
        :poll-state="pollState"
        @goto="goto"
        @refresh="refresh"
      >
        <HostInventoryStartConfirm
          v-if="canDiscover"
          :title="identity.confirmTitle.value"
          :label="startLabel"
          :disabled="!!startBlockedReason || active || starting"
          :loading="starting"
          :no-executor="identity.confirmNoExecutor.value"
          :fingerprint="showFingerprintLine ? 'none' : showFingerprintUnknown ? 'unknown' : ''"
          @confirm="start"
        />
      </HostInventoryStatusCard>

      <HostInventoryBanners
        :scan="scan"
        :coverage="view.coverage"
        :can-edit-asset="canEditAsset"
        :can-manage-executor="identity.canExecutor.value"
        :executor-name="identity.executorName.value"
        @goto="goto"
      />

      <!-- 從未盤點 -->
      <section
        v-if="!scan"
        class="inv-never"
        data-test="inv-never"
      >
        <p data-test="inv-never-card">
          {{ $t(identity.neverCardKey.value) }}
        </p>
        <p
          v-if="!canDiscover"
          class="inv-never-hint"
          data-test="inv-never-readonly"
        >
          {{ $t('hostInventory.never.readonly') }}
        </p>
      </section>

      <!-- 第一次盤點、還沒有任何結果：主體只放骨架列，不給數字與空狀態（避免盤點沒跑完就像「沒事」） -->
      <div
        v-else-if="showSkeleton"
        class="inv-skeleton-rows"
        role="status"
        :aria-label="$t('hostInventory.skeletonLabel')"
        data-test="inv-skeleton"
      >
        <div
          v-for="i in 4"
          :key="i"
          class="inv-skel-row"
        >
          <span
            v-for="w in SKELETON_COLS"
            :key="w"
            class="inv-skel-cell"
            :style="{ flex: w }"
          />
        </div>
      </div>

      <template v-else-if="showResults">
        <h3
          v-if="showPrevious"
          class="inv-prev"
          data-test="inv-prev"
        >
          {{ previousTitle }}
        </h3>

        <div
          v-if="resultScan"
          class="inv-counts"
        >
          <div class="inv-count">
            <strong>{{ resultScan.accounts_total }}</strong>
            <span>{{ $t('hostInventory.count.accounts') }}</span>
          </div>
          <div class="inv-count">
            <strong>{{ resultScan.privileged_total }}</strong>
            <span>{{ $t('hostInventory.count.privileged') }}</span>
          </div>
          <button
            type="button"
            class="inv-count is-warning is-link"
            data-test="inv-count-unmanaged"
            @click="setFilter('needs')"
          >
            <strong>{{ resultScan.unmanaged_privileged_total }}</strong>
            <span>{{ $t('hostInventory.count.unmanagedClickable') }}</span>
            <em
              v-if="newDelta > 0"
              class="inv-new"
              data-test="inv-new"
            >{{ $t('hostInventory.newCount', { n: newDelta }) }}</em>
          </button>
        </div>

        <div class="inv-filters">
          <el-radio-group
            :model-value="filter"
            size="small"
            data-test="inv-filters"
            @update:model-value="setFilter"
          >
            <el-radio-button
              v-for="f in FILTERS"
              :key="f"
              :value="f"
              :data-test="`inv-filter-${f}`"
            >
              {{ filterLabel(f) }}
            </el-radio-button>
          </el-radio-group>
          <el-input
            v-model="search"
            size="small"
            clearable
            class="inv-search"
            :placeholder="$t('hostInventory.search.placeholder')"
            data-test="inv-search"
          />
        </div>

        <HostInventoryResultTable
          :rows="rows"
          :filter="filter"
          :partial="resultScan?.status === 'partial'"
          :asset-name="asset?.name || ''"
          :can-discover="canDiscover"
          :can-manage="canManage"
          :show-manage="holdsDiscover"
          @manage="(f) => emit('manage', { finding: f, asset })"
          @ignore="openIgnore"
          @reopen="reopen"
        />

        <AppPagination
          v-if="view.total > view.page_size"
          class="inv-pagination"
          layout="prev, pager, next"
          :total="view.total"
          :page-size="view.page_size"
          :current-page="page"
          @current-change="onPage"
        />
      </template>

      <HostInventoryCoverage
        v-if="scan && !active && (view.coverage.length || scan.privileged_groups !== undefined)"
        v-model="openPanels"
        :coverage="view.coverage"
        :fixed-notes="view.fixed_notes"
        :privileged-groups="String(scan.privileged_groups ?? '')"
        :can-adjust-groups="canAdjustGroups"
        :can-manage-executor="identity.canExecutor.value"
        @goto="goto"
      />
    </template>

    <HostInventoryIgnoreDialog
      v-model="ignoreOpen"
      :asset-id="assetId"
      :asset-name="asset?.name || ''"
      :finding="ignoreTarget"
      @done="onIgnored"
      @gone="load"
      @denied="load"
    />
  </el-drawer>
</template>

<script setup>
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { t } from '@/i18n'
import { can } from '@/composables/useCapabilities'
import { getAsset, getAssetHostKey } from '@/api/assets'
import { listAssetAccounts } from '@/api/assetAccounts'
import {
  getAssetInventory,
  reopenInventoryFinding,
  startInventoryScan,
} from '@/api/hostInventory'
import { effectiveRotationChannel } from '@/constants/rotationChannel'
import { actionAllowed } from '@/utils/scopedAssets'
import { formatDateTime } from '@/utils/format'
import { visibleText } from '@/utils/visibleName'
import {
  FILTERS,
  filterParams,
  hostKeyState,
  isActiveStatus,
  isResultStatus,
  sortFindings,
} from '@/utils/hostInventoryPresentation'
import EmptyState from '@/components/EmptyState.vue'
import ReadonlyNote from '@/components/ReadonlyNote.vue'
import AppPagination from '@/components/AppPagination.vue'
import HostInventoryBanners from './HostInventoryBanners.vue'
import HostInventoryCoverage from './HostInventoryCoverage.vue'
import HostInventoryIgnoreDialog from './HostInventoryIgnoreDialog.vue'
import HostInventoryResultTable from './HostInventoryResultTable.vue'
import HostInventoryStatusCard from './HostInventoryStatusCard.vue'
import HostInventoryStartConfirm from './HostInventoryStartConfirm.vue'
import { useInventoryIdentity } from '@/composables/useInventoryIdentity'
import { startErrorView } from '@/utils/hostInventoryStartError'

const POLL_MS = 3000
const POLL_LIMIT_MS = 120000
const PAGE_SIZE = 50
// 骨架列各欄的寬度比例（帳號、uid、特權原因、狀態）
const SKELETON_COLS = [3, 1, 6, 2]

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  // 只收資產識別；名稱、位址、協定與旗標一律開啟時以 getAsset 讀取
  assetId: { type: [Number, String], default: 0 },
})
const emit = defineEmits(['update:modelValue', 'manage', 'goto'])

const phase = ref('loading') // loading | ready | forbidden | notfound | error
const asset = ref(null)
const accounts = ref([])
// 主機指紋記錄：'recorded'（有記錄）｜'none'（尚無記錄）｜'unknown'（讀不到，無法判斷）
const hostKey = ref('unknown')
const view = ref(emptyView())
const filter = ref('needs')
const page = ref(1)
const search = ref('')
const openPanels = ref([])
const starting = ref(false)
const startMessage = ref('')
const startMessageGoAccounts = ref(false)
const startMessageGoExecutor = ref(false)
const pollState = ref('idle') // idle | polling | timeout | failed
const newDelta = ref(0)
const ignoreOpen = ref(false)
const ignoreTarget = ref(null)
// 最近一次已有結果的盤點（完成或部分完成）；進行中、失敗、中斷時，數字取自它
const prevScan = ref(null)
// 這台是否留有先前盤點的結果（第一次盤點時為 false，主體改放骨架列）
const hasPrevious = ref(false)

let pollTimer = null
let pollStartedAt = 0
let loadSeq = 0

function emptyView() {
  return { scan: null, coverage: [], fixed_notes: [], findings: [], total: 0, page: 1, page_size: PAGE_SIZE, next_identity: undefined }
}

const scan = computed(() => view.value.scan)
const active = computed(() => !!scan.value && isActiveStatus(scan.value.status))
// 權限與可用條件（依這次讀到的詳情，不依開啟來源的列）
const canDiscover = computed(() => actionAllowed(asset.value, 'discover_accounts', can('account:discover')))
// 納管只給持主機帳號盤點權限點者；該台可不可做再看「管理帳號」
const holdsDiscover = computed(() => can('account:discover'))
const canManage = computed(() => actionAllowed(asset.value, 'manage_accounts', can('asset:update')))
const canEditAsset = computed(() => actionAllowed(asset.value, 'edit', can('asset:update')))
const canAdjustGroups = computed(() => can('securitypolicy:manage'))
const supported = computed(
  () => !!asset.value && asset.value.protocol === 'ssh' && effectiveRotationChannel(asset.value) === 'posix_ssh'
)
const defaultAccount = computed(() => accounts.value.find((a) => a.is_default) || null)
const defaultName = computed(() => (defaultAccount.value?.username || '').trim())

const identity = useInventoryIdentity({
  assetId: computed(() => props.assetId),
  open: computed(() => props.modelValue),
  nextIdentity: computed(() => view.value.next_identity),
  defaultName,
  canManageExecutor: () => can('asset:executor-manage'),
})
// 專用帳號與預設帳號都沒有才不能發起；讀取回應沒帶 next_identity 時只看預設帳號
const noIdentity = computed(() =>
  identity.identityKnown.value ? view.value.next_identity === null : !defaultAccount.value
)
const startBlockedReason = computed(() => {
  if (!supported.value) return t('hostInventory.err.platform')
  if (noIdentity.value) return t('hostInventory.never.noDefault')
  return ''
})
const startLabel = computed(() => {
  if (active.value) return t('hostInventory.btn.scanning')
  return scan.value ? t('hostInventory.btn.rescan') : t('hostInventory.btn.start')
})
// 確認了這台尚無指紋記錄時，提示這次登入會記下指紋；讀不到記錄時改說無法確認
const showFingerprintLine = computed(() => hostKey.value === 'none')
const showFingerprintUnknown = computed(() => hostKey.value === 'unknown')

// 數字與表格所屬的盤點：這次已有結果就是這次，否則是上一次（可能不知道，例如抽屜在進行中才開啟）
const resultScan = computed(() => (scan.value && isResultStatus(scan.value.status) ? scan.value : prevScan.value))
// 進行中、失敗、中斷時，下方顯示的是上一次留下來的結果
const showPrevious = computed(() => !!scan.value && !isResultStatus(scan.value.status) && hasPrevious.value)
const showResults = computed(() => !!scan.value && (isResultStatus(scan.value.status) || hasPrevious.value))
const showSkeleton = computed(() => active.value && !hasPrevious.value)
const previousTitle = computed(() => {
  const p = prevScan.value
  const time = p ? fmt(p.finished_at || p.started_at) : ''
  return time ? t('hostInventory.previousResult', { time }) : t('hostInventory.previousResultNoTime')
})
function filterLabel(f) {
  if (f !== 'needs') return t(`hostInventory.filter.${f}`)
  return resultScan.value
    ? t('hostInventory.filter.needs', { n: resultScan.value.unmanaged_privileged_total })
    : t('hostInventory.filter.needsNoCount')
}
const rows = computed(() => {
  const q = search.value.trim().toLowerCase()
  const list = sortFindings(view.value.findings)
  if (!q) return list
  return list.filter((f) => visibleText(f.username).toLowerCase().includes(q) || String(f.username).toLowerCase().includes(q))
})

function fmt(v) {
  return v ? formatDateTime(v) : ''
}

// 讀取 -------------------------------------------------------------
async function init() {
  stopPolling()
  phase.value = 'loading'
  asset.value = null
  view.value = emptyView()
  filter.value = 'needs'
  page.value = 1
  search.value = ''
  startMessage.value = ''
  newDelta.value = 0
  prevScan.value = null
  hasPrevious.value = false
  const seq = ++loadSeq
  try {
    const [a, list, inv, hk] = await Promise.all([
      getAsset(props.assetId, { skipErrorToast: true }),
      listAssetAccounts(props.assetId, { skipErrorToast: true }).catch(() => ({ data: [] })),
      getAssetInventory(props.assetId, { ...filterParams('needs'), page: 1, page_size: PAGE_SIZE }),
      // 尚無記錄（404 NOTFOUND_HOST_KEY）與讀取失敗分開判讀，前者才提示這次會記下指紋
      Promise.resolve()
        .then(() => getAssetHostKey(props.assetId))
        .then(
          () => 'recorded',
          (err) => hostKeyState(err)
        ),
    ])
    if (seq !== loadSeq) return
    asset.value = a
    accounts.value = Array.isArray(list?.data) ? list.data : Array.isArray(list) ? list : []
    hostKey.value = hk
    applyView(inv)
    if (scan.value && !isResultStatus(scan.value.status)) {
      hasPrevious.value = await probePrevious()
      if (seq !== loadSeq) return
    }
    phase.value = 'ready'
    afterApply()
  } catch (err) {
    if (seq !== loadSeq) return
    const status = err?.response?.status
    phase.value = status === 403 ? 'forbidden' : status === 404 ? 'notfound' : 'error'
  }
}

function applyView(inv) {
  view.value = {
    scan: inv?.scan || null,
    coverage: Array.isArray(inv?.coverage) ? inv.coverage : [],
    fixed_notes: Array.isArray(inv?.fixed_notes) ? inv.fixed_notes : [],
    findings: Array.isArray(inv?.findings) ? inv.findings : [],
    total: Number(inv?.total) || 0,
    page: Number(inv?.page) || 1,
    page_size: Number(inv?.page_size) || PAGE_SIZE,
    // 現在發起會用誰：缺席（undefined）與 null（兩種身分都沒有）要分開
    next_identity: inv?.next_identity,
  }
  if (view.value.scan && isResultStatus(view.value.scan.status)) {
    prevScan.value = view.value.scan
    hasPrevious.value = true
  }
  // 部分完成時，檢查範圍預設展開
  if (view.value.scan?.status === 'partial' && !openPanels.value.includes('coverage')) {
    openPanels.value = ['coverage']
  }
}

// 這次還沒有結果時，確認這台是否留有先前的結果（不帶篩選、只取一筆）；讀不到就當沒有
async function probePrevious() {
  try {
    const all = await getAssetInventory(props.assetId, { page: 1, page_size: 1 })
    return Number(all?.total) > 0
  } catch {
    return false
  }
}

// 載入或讀取後的收尾：進行中就（重新）開始輪詢
function afterApply() {
  if (active.value) startPolling()
  else stopPolling()
}

async function load() {
  const seq = ++loadSeq
  try {
    const inv = await getAssetInventory(props.assetId, { ...filterParams(filter.value), page: page.value, page_size: PAGE_SIZE })
    if (seq !== loadSeq) return
    applyView(inv)
    afterApply()
  } catch (err) {
    if (seq !== loadSeq) return
    phase.value = err?.response?.status === 404 ? 'notfound' : 'error'
  }
}

function setFilter(f) {
  filter.value = f
  page.value = 1
  void load()
}
function onPage(p) {
  page.value = p
  void load()
}
function refresh() {
  pollState.value = 'idle'
  void load()
}

// 輪詢 -------------------------------------------------------------
function stopPolling() {
  if (pollTimer) clearInterval(pollTimer)
  pollTimer = null
  if (pollState.value === 'polling') pollState.value = 'idle'
}
function startPolling() {
  if (pollTimer) return
  pollStartedAt = Date.now()
  pollState.value = 'polling'
  pollTimer = setInterval(tick, POLL_MS)
}
async function tick() {
  if (Date.now() - pollStartedAt >= POLL_LIMIT_MS) {
    stopPolling()
    pollState.value = 'timeout'
    return
  }
  const before = resultScan.value?.unmanaged_privileged_total ?? 0
  try {
    const inv = await getAssetInventory(props.assetId, { ...filterParams(filter.value), page: page.value, page_size: PAGE_SIZE })
    applyView(inv)
    if (!active.value) {
      stopPolling()
      pollState.value = 'idle'
      const after = scan.value?.unmanaged_privileged_total ?? 0
      newDelta.value = after > before ? after - before : 0
    }
  } catch {
    stopPolling()
    pollState.value = 'failed'
  }
}

// 發起 -------------------------------------------------------------
async function start() {
  if (starting.value) return
  starting.value = true
  startMessage.value = ''
  startMessageGoAccounts.value = false
  startMessageGoExecutor.value = false
  try {
    const rec = await startInventoryScan(props.assetId)
    // 這次的紀錄取代狀態卡；上一次的數字留在 prevScan，不沿用到這次
    view.value = { ...view.value, scan: { ...(rec || {}), status: rec?.status || 'queued' } }
    pollState.value = 'idle'
    startPolling()
  } catch (err) {
    const v = startErrorView(err)
    startMessage.value = v.message
    startMessageGoAccounts.value = v.goAccounts
    startMessageGoExecutor.value = v.goExecutor
    if (v.reload) await load()
  } finally {
    starting.value = false
  }
}

// 處置 -------------------------------------------------------------
function openIgnore(f) {
  ignoreTarget.value = f
  ignoreOpen.value = true
}
function onIgnored() {
  void load()
}
async function reopen(f) {
  try {
    await reopenInventoryFinding(props.assetId, f.id)
    ElMessage.success(t('hostInventory.reopen.success', { name: visibleText(f.username) }))
    await load()
  } catch (err) {
    const code = err?.response?.data?.code
    const status = err?.response?.status
    if (code === 'NOTFOUND_INVENTORY_FINDING' || code === 'VALIDATION_INVALID_FINDING_ID') {
      ElMessage.error(t('hostInventory.err.itemGone'))
      await load()
    } else if (status === 403 || status === 404) {
      ElMessage.error(t('hostInventory.err.notInScope'))
    } else {
      ElMessage.error(t('hostInventory.err.generic'))
    }
  }
}

function goto(target) {
  emit('goto', { id: Number(props.assetId), target })
}

watch(
  () => [props.modelValue, props.assetId],
  ([open]) => {
    if (open && props.assetId) void init()
    else stopPolling()
  },
  { immediate: true }
)

onBeforeUnmount(stopPolling)

defineExpose({ reload: load })
</script>

<style scoped>
.inv-title h2 {
  margin: 0;
  font-size: 18px;
}

.inv-subtitle {
  display: block;
  margin-top: 2px;
  font-size: 13px;
  color: var(--ot-text-secondary);
}

.inv-load-error {
  display: flex;
  align-items: center;
  gap: 12px;
  color: var(--ot-danger);
}

.inv-never {
  padding: 16px;
  line-height: 1.7;
  color: var(--ot-text-secondary);
}

.inv-never-hint {
  color: var(--ot-text-disabled);
}

.inv-skeleton-rows {
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  overflow: hidden;
}

.inv-skel-row {
  display: flex;
  gap: 16px;
  padding: 14px 12px;
  border-bottom: 1px solid var(--ot-border-subtle);
}

.inv-skel-row:last-child {
  border-bottom: none;
}

.inv-skel-cell {
  height: 12px;
  border-radius: var(--ot-radius-sm, 4px);
  background: var(--ot-bg-surface);
  animation: inv-skel-pulse 1.4s ease-in-out infinite;
}

@keyframes inv-skel-pulse {
  50% {
    opacity: 0.5;
  }
}

.inv-prev {
  margin: 8px 0;
  font-size: 14px;
  color: var(--ot-text-secondary);
}

.inv-counts {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 12px;
  margin-bottom: 12px;
}

.inv-count {
  position: relative;
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 10px 12px;
  text-align: left;
  color: var(--ot-text-primary);
  background: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}

.inv-count strong {
  font-size: 22px;
}

.inv-count span {
  font-size: 12px;
  color: var(--ot-text-secondary);
}

.inv-count.is-warning strong {
  color: var(--ot-warning);
}

.inv-count.is-link {
  cursor: pointer;
}

.inv-new {
  position: absolute;
  top: 8px;
  right: 10px;
  font-style: normal;
  font-size: 12px;
  color: var(--ot-warning);
  animation: inv-fade 2s ease-out forwards;
}

@keyframes inv-fade {
  to {
    opacity: 0.2;
  }
}

.inv-filters {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  margin-bottom: 10px;
  flex-wrap: wrap;
}

.inv-search {
  width: 200px;
}

.inv-pagination {
  margin-top: 12px;
  justify-content: flex-end;
}
</style>
