<template>
  <div class="account-inventory">
    <PageHeader
      :title="$t('menu.hostAccountInventory')"
      :description="$t('hostInventory.global.subtitle')"
    >
      <template #actions>
        <el-button
          :loading="loading"
          data-test="ai-refresh"
          @click="load"
        >
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>
    <ReadonlyNote
      v-if="!canDiscover"
      data-test="ai-readonly"
    >
      {{ $t('hostInventory.readonlyNote') }}
    </ReadonlyNote>

    <!-- 本版只有「待處理」一段：全域清單端點沒有處置狀態參數，已忽略的結果到各台的盤點畫面看 -->
    <div
      class="ai-tabs"
      role="tablist"
    >
      <span
        class="ai-tab is-active"
        role="tab"
        aria-selected="true"
        data-test="ai-tab-open"
      >{{ $t('hostInventory.global.tabOpen') }} ({{ total }})</span>
    </div>

    <el-alert
      v-if="loadError"
      type="error"
      show-icon
      :closable="false"
      data-test="ai-error"
      :title="$t('hostInventory.global.loadFailed')"
    >
      <el-button
        size="small"
        type="primary"
        data-test="ai-retry"
        @click="load"
      >
        {{ $t('hostInventory.btn.retry') }}
      </el-button>
    </el-alert>

    <template v-else-if="loaded">
      <div
        v-if="rows.length"
        v-loading="loading"
      >
        <el-alert
          type="warning"
          show-icon
          :closable="false"
          class="ai-incomplete"
          data-test="ai-incomplete"
          :title="$t('hostInventory.global.incompleteNote')"
        />
        <table
          class="ai-table"
          data-test="ai-table"
        >
          <caption
            class="ai-caption"
            data-test="ai-caption"
          >
            {{ $t('hostInventory.caption.global') }}
          </caption>
          <thead>
            <tr>
              <th scope="col">
                {{ $t('hostInventory.col.account') }}
              </th>
              <th scope="col">
                {{ $t('hostInventory.col.asset') }}
              </th>
              <th scope="col">
                {{ $t('hostInventory.col.reasons') }}
              </th>
              <th scope="col">
                {{ $t('hostInventory.col.login') }}
              </th>
              <th scope="col">
                {{ $t('hostInventory.col.firstSeen') }}
              </th>
              <th
                scope="col"
                data-test="ai-col-last"
              >
                {{ $t('hostInventory.col.lastSeen') }}
              </th>
              <th scope="col">
                {{ $t('hostInventory.col.actions') }}
              </th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="f in rows"
              :key="f.id"
              data-test="ai-row"
            >
              <td>
                <div class="ai-name">
                  <HostInventoryName :value="f.username" />
                  <el-button
                    link
                    size="small"
                    :title="$t('hostInventory.cell.copy')"
                    :aria-label="$t('hostInventory.cell.copy')"
                    data-test="ai-copy"
                    @click="copyName(f)"
                  >
                    <Copy
                      :size="13"
                      aria-hidden="true"
                    />
                  </el-button>
                </div>
              </td>
              <td>
                <el-button
                  link
                  type="primary"
                  data-test="ai-asset"
                  @click="openDrawer(f.asset_id)"
                >
                  {{ assetName(f.asset_id) }}
                </el-button>
                <div
                  v-if="assetHost(f.asset_id)"
                  class="ai-host"
                >
                  {{ assetHost(f.asset_id) }}
                </div>
              </td>
              <td>
                <HostInventoryReasons :reasons="f.privileged_reasons" />
                <el-tag
                  v-if="f.incomplete"
                  size="small"
                  type="warning"
                  effect="plain"
                  data-test="ai-incomplete-badge"
                  :title="$t('hostInventory.cell.incompleteTip')"
                >
                  {{ $t('hostInventory.cell.incomplete') }}
                </el-tag>
              </td>
              <td>
                {{ f.login_capable ? $t('hostInventory.cell.canLogin') : $t('hostInventory.cell.cannotLogin') }}
              </td>
              <td>{{ formatDate(f.first_seen_at) }}</td>
              <td
                :class="{ 'is-stale': isStale(f.last_seen_at) }"
                data-test="ai-last"
              >
                {{ lastSeenText(f.last_seen_at) }}
              </td>
              <td>
                <div class="ai-actions">
                  <el-button
                    v-if="canManageGlobal"
                    v-preview-write
                    link
                    type="primary"
                    size="small"
                    data-test="ai-manage"
                    @click="manage(f)"
                  >
                    {{ $t('hostInventory.action.manage') }}
                  </el-button>
                  <el-button
                    v-if="canDiscover"
                    v-preview-write
                    link
                    size="small"
                    data-test="ai-ignore"
                    @click="openIgnore(f)"
                  >
                    {{ $t('hostInventory.action.ignore') }}
                  </el-button>
                  <el-button
                    link
                    type="primary"
                    size="small"
                    data-test="ai-view"
                    @click="openDrawer(f.asset_id)"
                  >
                    {{ $t('hostInventory.action.viewHost') }}
                  </el-button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
        <AppPagination
          v-if="total > pageSize"
          class="ai-pagination"
          layout="total, prev, pager, next"
          :total="total"
          :page-size="pageSize"
          :current-page="page"
          @current-change="onPage"
        />
      </div>

      <div
        v-else
        class="ai-empty"
        data-test="ai-empty"
      >
        <p class="ai-empty-title">
          {{ $t('hostInventory.global.empty') }}
        </p>
        <p class="ai-empty-hint">
          {{ $t('hostInventory.global.emptyHint') }}
        </p>
        <p
          class="ai-empty-warn"
          data-test="ai-empty-incomplete"
        >
          {{ $t('hostInventory.global.incompleteNote') }}
        </p>
        <el-button
          data-test="ai-go-assets"
          @click="router.push('/assets')"
        >
          {{ $t('hostInventory.global.goAssets') }}
        </el-button>
      </div>
    </template>

    <HostAccountInventoryDrawer
      v-model="drawerOpen"
      :asset-id="drawerAssetId"
      @manage="onDrawerManage"
      @goto="onDrawerGoto"
    />
    <HostInventoryIgnoreDialog
      v-model="ignoreOpen"
      :asset-id="ignoreTarget?.asset_id || 0"
      :asset-name="assetName(ignoreTarget?.asset_id)"
      :finding="ignoreTarget"
      @done="onIgnored"
      @gone="load"
      @denied="load"
    />
  </div>
</template>

<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Copy } from 'lucide-vue-next'
import PageHeader from '@/components/PageHeader.vue'
import ReadonlyNote from '@/components/ReadonlyNote.vue'
import AppPagination from '@/components/AppPagination.vue'
import HostAccountInventoryDrawer from '@/components/asset/HostAccountInventoryDrawer.vue'
import HostInventoryIgnoreDialog from '@/components/asset/HostInventoryIgnoreDialog.vue'
import HostInventoryName from '@/components/asset/HostInventoryName.vue'
import HostInventoryReasons from '@/components/asset/HostInventoryReasons.vue'
import { listGlobalInventoryFindings } from '@/api/hostInventory'
import { getAsset } from '@/api/assets'
import { can } from '@/composables/useCapabilities'
import { previewWrite as vPreviewWrite } from '@/directives/previewWrite'
import { formatDate } from '@/utils/format'
import { visibleText } from '@/utils/visibleName'
import { stashManagePrefill } from '@/utils/inventoryManageHandoff'
import { actionAllowed, actionDenial, denialText } from '@/utils/scopedAssets'

// 主機帳號盤點全域頁：已盤點的主機上、有管理權限但還沒有納管的帳號（待處理）。
// 盤點本身只能從資產頁或這裡的抽屜、一台一台發起。

const { t } = useI18n()
const router = useRouter()

const PAGE_SIZE = 20
const STALE_DAYS = 30
const DAY_MS = 86400000

const rows = ref([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(PAGE_SIZE)
const loading = ref(false)
const loaded = ref(false)
const loadError = ref(false)
let loadSeq = 0

const canDiscover = computed(() => can('account:discover'))
// 納管只給持主機帳號盤點權限點者；全域頁的結果列不是資產列、沒有旗標，
// 先以全域 asset:update 呈現，按下時再讀詳情旗標
const canManageGlobal = computed(() => canDiscover.value && can('asset:update'))

// 資產名稱與位址：全域回應不含，依資產識別去重後各讀一次
const assets = ref({})
const requested = new Set()

async function fetchAssetInfo(ids) {
  await Promise.all(
    ids
      .filter((id) => !requested.has(id))
      .map(async (id) => {
        requested.add(id)
        try {
          const a = await getAsset(id, { skipErrorToast: true })
          assets.value = { ...assets.value, [id]: { name: a?.name || '', host: a?.host || '' } }
        } catch {
          // 讀不到就用「資產 #id」的退路名稱
        }
      })
  )
}

function assetName(id) {
  if (!id) return ''
  const a = assets.value[id]
  return a?.name || t('hostInventory.global.assetFallback', { id })
}
function assetHost(id) {
  return assets.value[id]?.host || ''
}

async function load() {
  const seq = ++loadSeq
  loading.value = true
  loadError.value = false
  try {
    const res = await listGlobalInventoryFindings({ page: page.value, page_size: pageSize.value })
    if (seq !== loadSeq) return
    rows.value = res?.findings || []
    total.value = Number(res?.total) || 0
    loaded.value = true
    void fetchAssetInfo([...new Set(rows.value.map((f) => f.asset_id))])
  } catch {
    if (seq !== loadSeq) return
    loadError.value = true
  } finally {
    if (seq === loadSeq) loading.value = false
  }
}

function onPage(p) {
  page.value = p
}
watch(page, load)
onMounted(load)

// 最近看到：全域列沒有該台最近盤點時間，這欄如實顯示該筆最近一次在主機上看到的時間（last_seen_at）；超過 30 天以警示色標示
function daysSince(iso) {
  const ts = Date.parse(iso)
  if (Number.isNaN(ts)) return null
  return Math.max(0, Math.floor((Date.now() - ts) / DAY_MS))
}
function isStale(iso) {
  const d = daysSince(iso)
  return d !== null && d > STALE_DAYS
}
function lastSeenText(iso) {
  const d = daysSince(iso)
  if (d === null) return t('hostInventory.cell.none')
  return d === 0 ? t('hostInventory.global.lastSeenToday') : t('hostInventory.global.lastSeenDays', { n: d })
}

async function copyName(f) {
  try {
    await navigator.clipboard.writeText(f.username)
    ElMessage.success(t('hostInventory.cell.copied'))
  } catch {
    // 剪貼簿不可用時不打擾使用者
  }
}

// --- 查看這台：在本頁開同一個盤點抽屜，不換頁；關閉後重讀清單 ---
const drawerOpen = ref(false)
const drawerAssetId = ref(0)
function openDrawer(id) {
  drawerAssetId.value = Number(id)
  drawerOpen.value = true
}
watch(drawerOpen, (open, was) => {
  if (was && !open) void load()
})
function onDrawerGoto({ id }) {
  drawerOpen.value = false
  router.push({ path: '/assets', query: { edit: String(id) } })
}

// --- 忽略 ---
const ignoreOpen = ref(false)
const ignoreTarget = ref(null)
function openIgnore(f) {
  ignoreTarget.value = f
  ignoreOpen.value = true
}
function onIgnored() {
  const f = ignoreTarget.value
  ElMessage.success(t('hostInventory.ignore.success', { name: visibleText(f?.username || '') }))
  rows.value = rows.value.filter((r) => r.id !== f?.id)
  total.value = Math.max(0, total.value - 1)
  if (!rows.value.length && total.value > 0) void load()
}

// --- 納管：先讀詳情確認「管理帳號」可做，再寫一次性暫存並前往資產頁 ---
async function goManage(finding) {
  stashManagePrefill({ assetId: finding.asset_id, username: finding.username, privileged: finding.privileged !== false })
  await router.push({ path: '/assets', query: { edit: String(finding.asset_id) } })
}
async function manage(f) {
  if (!canManageGlobal.value) return
  try {
    const detail = await getAsset(f.asset_id, { skipErrorToast: true })
    if (!actionAllowed(detail, 'manage_accounts', can('asset:update'))) {
      ElMessage.warning(denialText(t, actionDenial(detail, 'manage_accounts')) || t('hostInventory.action.manageDenied'))
      return
    }
  } catch {
    ElMessage.warning(t('hostInventory.err.readFailed'))
    return
  }
  await goManage(f)
}
function onDrawerManage({ finding, asset }) {
  drawerOpen.value = false
  void goManage({ ...finding, asset_id: finding.asset_id ?? asset?.id })
}
</script>

<style scoped>
.ai-tabs {
  display: flex;
  gap: 16px;
  margin-bottom: var(--ot-space-md);
  border-bottom: 1px solid var(--ot-border);
}

.ai-tab {
  padding: 8px 2px;
  font-size: 14px;
  color: var(--ot-text-secondary);
}

.ai-tab.is-active {
  color: var(--el-color-primary);
  border-bottom: 2px solid var(--el-color-primary);
}

.ai-incomplete {
  margin-bottom: var(--ot-space-md);
}

.ai-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}

/* 表格標題只給輔助技術讀，畫面上不佔位 */
.ai-caption {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

.ai-table th {
  text-align: left;
  padding: 8px 6px;
  font-weight: 500;
  color: var(--ot-text-secondary);
  border-bottom: 1px solid var(--ot-border);
}

.ai-table td {
  padding: 8px 6px;
  vertical-align: top;
  border-bottom: 1px solid var(--ot-border-subtle);
}

.ai-name {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 4px;
}

.ai-host {
  font-size: 12px;
  color: var(--ot-text-secondary);
}

.ai-actions {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
}

.is-stale {
  color: var(--ot-warning);
  font-weight: 500;
}

.ai-pagination {
  margin-top: var(--ot-space-md);
  justify-content: flex-end;
}

.ai-empty {
  padding: var(--ot-space-xl, 32px) var(--ot-space-md);
  text-align: center;
  border: 1px solid var(--ot-border);
  border-radius: var(--ot-radius-md, 6px);
}

.ai-empty-title {
  font-size: 15px;
  font-weight: 500;
  margin: 0 0 4px;
}

.ai-empty-hint {
  margin: 0 0 8px;
  color: var(--ot-text-secondary);
}

.ai-empty-warn {
  margin: 0 0 16px;
  color: var(--ot-warning);
  font-size: 13px;
}
</style>
