<template>
  <div class="credential-library">
    <PageHeader
      :title="t('menu.credentials')"
      :description="t('credentials.description')"
    >
      <template #actions>
        <el-button
          data-test="refresh"
          @click="refresh"
        >
          <el-icon><RotateCw /></el-icon>
          {{ t('common.refresh') }}
        </el-button>
        <el-button
          type="primary"
          data-test="create-credential"
          @click="openCreate"
        >
          <el-icon><Plus /></el-icon>
          {{ t('credentials.create') }}
        </el-button>
      </template>
    </PageHeader>

    <div class="toolbar">
      <div class="filter">
        <span class="filter-label">{{ t('credentials.filterSearch') }}</span>
        <el-input
          v-model="filters.search"
          class="search"
          clearable
          :placeholder="t('credentials.searchPlaceholder')"
          data-test="filter-search"
          @keyup.enter="applyFilters"
          @clear="applyFilters"
        />
      </div>
      <div class="filter">
        <span class="filter-label">{{ t('credentials.scope') }}</span>
        <el-select
          v-model="filters.scope"
          class="scope"
          :empty-values="[null, undefined]"
          :placeholder="t('common.all')"
          data-test="filter-scope"
          @change="applyFilters"
        >
          <el-option
            :label="t('common.all')"
            value=""
          />
          <el-option
            v-for="value in CREDENTIAL_SCOPE_VALUES"
            :key="value"
            :label="t(`enum.credentialScope.${value}`)"
            :value="value"
          />
        </el-select>
      </div>
      <div class="filter">
        <span class="filter-label">{{ t('credentials.filterSecretType') }}</span>
        <el-select
          v-model="filters.secret_type"
          class="secret-type"
          :empty-values="[null, undefined]"
          :placeholder="t('common.all')"
          data-test="filter-secret-type"
          @change="applyFilters"
        >
          <el-option
            :label="t('common.all')"
            value=""
          />
          <el-option
            v-for="value in CREDENTIAL_SECRET_TYPE_VALUES"
            :key="value"
            :label="t(`enum.credentialSecretType.${value}`)"
            :value="value"
          />
        </el-select>
      </div>
      <div class="filter">
        <span class="filter-label">{{ t('credentials.filterRotationState') }}</span>
        <el-select
          v-model="filters.rotation_state"
          class="rotation-state"
          :empty-values="[null, undefined]"
          :placeholder="t('common.all')"
          data-test="filter-rotation-state"
          @change="applyFilters"
        >
          <el-option
            :label="t('common.all')"
            value=""
          />
          <el-option
            v-for="value in CREDENTIAL_AGGREGATE_STATE_VALUES"
            :key="value"
            :label="t(`enum.credentialAggregateState.${value}`)"
            :value="value"
          />
        </el-select>
      </div>
      <el-button
        type="primary"
        data-test="filter-apply"
        @click="applyFilters"
      >
        {{ t('common.search') }}
      </el-button>
      <el-button
        data-test="filter-reset"
        @click="resetFilters"
      >
        {{ t('common.reset') }}
      </el-button>
    </div>

    <!-- 載入失敗要說出來：把清單清空而不出聲，畫面會變成「這裡沒有憑證」，
         那是一句與事實相反的話 -->
    <el-alert
      v-if="listError"
      type="error"
      :closable="false"
      show-icon
      class="list-error"
      :title="listError"
      data-test="list-error"
    />

    <div class="split">
      <div class="pane list-pane">
        <CredentialTable
          :credentials="credentials"
          :loading="listLoading"
          :load-error="!!listError"
          :selected-id="selectedId"
          :page="page"
          :page-size="pageSize"
          :total="total"
          @select="selectCredential"
          @update:page="changePage"
          @update:page-size="changePageSize"
        />
      </div>
      <div
        v-loading="detailLoading"
        class="pane detail-pane"
      >
        <CredentialDetailPanel
          :credential="detail"
          :aggregate-state="aggregateState"
          @edit="openEdit"
          @changed="onDetailChanged"
          @deleted="onDeleted"
        />
      </div>
    </div>

    <CredentialFormDialog
      v-model="formVisible"
      :credential="formTarget"
      @saved="onSaved"
    />
  </div>
</template>

<script setup>
/**
 * 帳號憑證庫（設計稿 01 主從檢視）。
 *
 * 左表是全部登入憑證、右詳情是選中那一筆的掛載與動作。之所以是主從而非
 * 「列表頁 ＋ 詳情頁」：管理者的實際工作是「這組帳密到底在哪幾台上」，
 * 而那個問題要在不離開清單的情況下逐筆問過去。
 *
 * 篩選與分頁一律送到伺服端（範圍、型別、輪替狀態、關鍵字），總數取自
 * 回應。伺服端查詢採後發者為準：連續輸入時先發的回應可能後到，若不丟棄就會用
 * 舊條件的結果覆蓋畫面。
 */
import { onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { Plus, RotateCw } from 'lucide-vue-next'
import PageHeader from '@/components/PageHeader.vue'
import CredentialTable from '@/components/credential/CredentialTable.vue'
import CredentialDetailPanel from '@/components/credential/CredentialDetailPanel.vue'
import CredentialFormDialog from '@/components/credential/CredentialFormDialog.vue'
import { listCredentials, getCredential } from '@/api/credentials'
import {
  CREDENTIAL_SCOPE_VALUES,
  CREDENTIAL_SECRET_TYPE_VALUES,
  CREDENTIAL_AGGREGATE_STATE_VALUES,
} from '@/constants/credentials'

const { t } = useI18n()

const credentials = ref([])
const listLoading = ref(false)
const listError = ref('')
const detail = ref(null)
const detailLoading = ref(false)
const aggregateState = ref('')
const selectedId = ref(null)
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
const formVisible = ref(false)
const formTarget = ref(null)

// 沒有獨立的帳號名欄位：關鍵字搜尋同時比對名稱與帳號名，兩個入口做同一件事
// 只會讓人猜哪一個才是精確比對
const filters = reactive({ search: '', scope: '', secret_type: '', rotation_state: '' })

let listSeq = 0

async function loadList() {
  const seq = ++listSeq
  listLoading.value = true
  try {
    const res = await listCredentials({
      search: filters.search || undefined,
      scope: filters.scope || undefined,
      secret_type: filters.secret_type || undefined,
      rotation_state: filters.rotation_state || undefined,
      page: page.value,
      page_size: pageSize.value,
    })
    if (seq !== listSeq) return
    credentials.value = res?.data || []
    listError.value = ''
    // 總數以回應為準；缺欄時退回本次拿到的筆數，不憑空生一個更大的數字
    total.value = typeof res?.total === 'number' ? res.total : credentials.value.length
  } catch (err) {
    console.error('[CredentialLibrary] 載入憑證失敗:', err)
    if (seq === listSeq) {
      credentials.value = []
      total.value = 0
      listError.value = t('credentials.loadFailed')
    }
  } finally {
    if (seq === listSeq) listLoading.value = false
  }
}

async function loadDetail(id) {
  if (!id) {
    detail.value = null
    aggregateState.value = ''
    return
  }
  detailLoading.value = true
  try {
    const res = await getCredential(id)
    detail.value = res?.data || null
    aggregateState.value = res?.aggregate_state || ''
  } catch (err) {
    console.error('[CredentialLibrary] 載入憑證詳情失敗:', err)
    detail.value = null
    aggregateState.value = ''
  } finally {
    detailLoading.value = false
  }
}

async function selectCredential(row) {
  if (!row || row.id === selectedId.value) return
  selectedId.value = row.id
  await loadDetail(row.id)
}

async function applyFilters() {
  page.value = 1
  await loadList()
}

async function resetFilters() {
  filters.search = ''
  filters.scope = ''
  filters.secret_type = ''
  filters.rotation_state = ''
  await applyFilters()
}

async function changePage(next) {
  page.value = next
  await loadList()
}

async function changePageSize(size) {
  pageSize.value = size
  page.value = 1
  await loadList()
}

async function refresh() {
  await Promise.all([loadList(), loadDetail(selectedId.value)])
}

function openCreate() {
  formTarget.value = null
  formVisible.value = true
}

function openEdit(credential) {
  formTarget.value = credential
  formVisible.value = true
}

async function onSaved() {
  await refresh()
}

async function onDetailChanged() {
  await refresh()
}

// 刪掉的那一筆不再有詳情可看：清空選取而不是留著一個指向不存在資料的面板
async function onDeleted() {
  selectedId.value = null
  detail.value = null
  aggregateState.value = ''
  await loadList()
}

onMounted(loadList)

defineExpose({
  credentials, detail, aggregateState, selectedId, filters, total, listError,
  loadList, loadDetail, selectCredential, applyFilters, resetFilters, refresh,
  openCreate, openEdit, onDeleted, changePage, changePageSize, page, pageSize,
})
</script>

<style scoped>
.credential-library {
  display: flex;
  flex-direction: column;
  /* 主從檢視要滿版：兩側各自捲動，頁面本身不捲——否則右詳情會被左表的長度推走 */
  height: 100%;
  min-height: 0;
}

.toolbar {
  display: flex;
  align-items: center;
  gap: var(--ot-space-md);
  margin-bottom: var(--ot-space-md);
  padding: var(--ot-space-md);
  background: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.filter {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
}

.filter-label {
  font-size: var(--ot-font-size-md);
  color: var(--ot-text-secondary);
  white-space: nowrap;
}

.search {
  width: 200px;
}

.scope {
  width: 120px;
}

.secret-type {
  width: 120px;
}

.rotation-state {
  width: 140px;
}

.list-error {
  margin-bottom: var(--ot-space-md);
}

.split {
  display: flex;
  flex: 1;
  gap: var(--ot-space-md);
  align-items: stretch;
  min-height: 0;
}

.pane {
  background: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  min-height: 0;
}

.list-pane {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.detail-pane {
  width: 400px;
  overflow: hidden;
  flex-shrink: 0;
  padding: var(--ot-space-md);
  display: flex;
  flex-direction: column;
}
</style>
