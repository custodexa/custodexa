<template>
  <el-drawer
    :model-value="modelValue"
    :title="$t('workspace.fileManager')"
    size="520px"
    @update:model-value="$emit('update:modelValue', $event)"
    @open="refresh"
  >
    <!-- 目前檔案操作所用的帳號（asset-multi-account D9）：終端與檔案面用不同
         身分是審計語義的斷裂，故明示——自會話進入沿用該會話帳號，
         獨立入口走預設帳號 -->
    <div class="file-account">
      <el-icon><User /></el-icon>
      <span>{{
        accountUsername
          ? $t('fileManager.accountSession', { username: accountUsername })
          : $t('fileManager.accountDefault')
      }}</span>
    </div>

    <!-- 資料傳輸能力提示（data-transfer-control 6.2）：哪些動作被政策擋下先講明白，
         不讓使用者點下去才吃 403。瀏覽與列目錄不受此區塊影響 -->
    <el-alert
      v-if="deniedFileActions.length"
      class="file-caps-alert"
      type="warning"
      :closable="false"
      show-icon
      :title="$t('transferCapability.blockedTitle')"
      :description="$t('transferCapability.blockedDesc', { actions: deniedActionLabels })"
    />

    <div class="file-toolbar">
      <el-breadcrumb separator="/">
        <el-breadcrumb-item>
          <el-link @click="navigateTo('/')">
            /
          </el-link>
        </el-breadcrumb-item>
        <el-breadcrumb-item
          v-for="crumb in breadcrumbs"
          :key="crumb.path"
        >
          <el-link @click="navigateTo(crumb.path)">
            {{ crumb.name }}
          </el-link>
        </el-breadcrumb-item>
      </el-breadcrumb>

      <div class="file-actions">
        <el-tooltip
          :disabled="canUpload"
          :content="$t('transferCapability.deniedReason')"
        >
          <span>
            <el-upload
              :show-file-list="false"
              :disabled="!canUpload"
              :http-request="handleUpload"
            >
              <el-button
                size="small"
                type="primary"
                :disabled="!canUpload"
              >
                {{ $t('workspace.uploadConfirm') }}
              </el-button>
            </el-upload>
          </span>
        </el-tooltip>
        <el-tooltip
          :disabled="canUpload"
          :content="$t('transferCapability.deniedReason')"
        >
          <span>
            <el-button
              size="small"
              :disabled="!canUpload"
              @click="handleMkdir"
            >
              {{ $t('fileManager.mkdir') }}
            </el-button>
          </span>
        </el-tooltip>
        <el-button
          size="small"
          @click="refresh"
        >
          {{ $t('common.refresh') }}
        </el-button>
      </div>
    </div>

    <el-table
      v-loading="loading"
      :data="entries"
      size="small"
      @row-dblclick="handleRowOpen"
    >
      <el-table-column
        :label="$t('common.name')"
        min-width="180"
      >
        <template #default="{ row }">
          <el-link
            v-if="row.is_dir"
            type="primary"
            @click="enterDir(row)"
          >
            {{ row.name }}/
          </el-link>
          <span v-else>{{ row.name }}</span>
        </template>
      </el-table-column>
      <el-table-column
        :label="$t('fileManager.sizeColumn')"
        width="90"
      >
        <template #default="{ row }">
          {{ row.is_dir ? '-' : formatSize(row.size) }}
        </template>
      </el-table-column>
      <el-table-column
        :label="$t('fileManager.modTimeColumn')"
        width="150"
      >
        <template #default="{ row }">
          {{ formatTime(row.mod_time) }}
        </template>
      </el-table-column>
      <el-table-column
        :label="$t('common.actions')"
        width="110"
        fixed="right"
      >
        <template #default="{ row }">
          <el-button
            v-if="!row.is_dir"
            size="small"
            link
            type="primary"
            :disabled="!canDownload"
            :title="canDownload ? '' : $t('transferCapability.deniedReason')"
            @click="handleDownload(row)"
          >
            {{ $t('workspace.downloadConfirm') }}
          </el-button>
          <el-button
            size="small"
            link
            type="danger"
            :disabled="!canDelete"
            :title="canDelete ? '' : $t('transferCapability.deniedReason')"
            @click="handleDelete(row)"
          >
            {{ $t('common.delete') }}
          </el-button>
        </template>
      </el-table-column>
      <template #empty>
        <span>{{ $t('fileManager.emptyDir') }}</span>
      </template>
    </el-table>
  </el-drawer>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { User } from '@element-plus/icons-vue'
import { listFiles, uploadFile, downloadFile, mkdir, deleteFile } from '@/api/files'
import { useTransferCapabilities } from '@/composables/useTransferCapabilities'
import { t, currentLocale } from '@/i18n'

const props = defineProps({
  assetId: {
    type: [Number, String],
    required: true
  },
  modelValue: {
    type: Boolean,
    default: false
  },
  // 會話帳號沿用（asset-multi-account D9）：自會話分頁進入時帶該會話 ID，
  // 後端依會話帳號快照決定用哪個帳號；獨立入口不帶＝走預設帳號
  sessionId: {
    type: [Number, String],
    default: null
  },
  // 目前檔案操作所用的帳號（僅顯示用，非判定依據——真正的帳號由後端依
  // session_id 解析。空值＝預設帳號）
  accountUsername: {
    type: String,
    default: ''
  }
})

defineEmits(['update:modelValue'])

// 身分鍵：props.sessionId 可能是字串（route/prop 型別鬆散），一律正規化成
// 數字或 null，否則 '42' 與 42 會被誤判成兩種身分而無限重載
const sessionKey = computed(() => (props.sessionId ? Number(props.sessionId) : null))

const currentPath = ref('/')
const entries = ref([])
const loading = ref(false)

// 資料傳輸有效能力（data-transfer-control 6.2）：**呈現用，非強制點**——
// 真正的閘在後端四個檔案端點，前端把不可用動作先標成不可用只是為了不讓
// 使用者做白工。Mkdir 併入 file_upload 判定（D3 註 2），故與上傳共用 canUpload
const { load: loadCapabilities, allows, deniedActions } = useTransferCapabilities()
const canUpload = computed(() => allows('file_upload'))
const canDownload = computed(() => allows('file_download'))
const canDelete = computed(() => allows('file_delete'))
// 檔案面被擋的動作（剪貼簿兩鍵與本面板無關，不混進來）
const deniedFileActions = computed(() => deniedActions.value.filter((a) => a.startsWith('file_')))
// 被擋動作的顯示名（Mkdir 屬上傳判定，故不另列）
const deniedActionLabels = computed(() =>
  deniedFileActions.value
    .map((a) => t(`transferCapability.action.${a}`))
    .join(t('transferCapability.separator'))
)

const breadcrumbs = computed(() => {
  const segments = currentPath.value.split('/').filter(Boolean)
  return segments.map((name, i) => ({
    name,
    path: '/' + segments.slice(0, i + 1).join('/')
  }))
})

function joinPath(dir, name) {
  return dir === '/' ? `/${name}` : `${dir}/${name}`
}

// 目前清單是以哪個身分載入的（asset-multi-account D9 對抗審查 HIGH-1）。
// undefined＝尚未載入；null＝以預設帳號載入；數字＝以該 session 的帳號載入
const loadedSessionId = ref(undefined)

// 清單身分是否已與現行 props 不符——不符時畫面上的檔案清單屬於另一個帳號
const identityStale = computed(() => loadedSessionId.value !== sessionKey.value)

async function refresh() {
  const identity = sessionKey.value
  loading.value = true
  // 能力與清單同批取得（data-transfer-control 6.2／D4 逐次判定）：政策可在會話
  // 進行中改動且檔案三鍵即時生效，故不在開啟面板時取一次就當定局——每次重新整理
  // 或切目錄都重取，呈現才跟得上伺服端的實際判定
  loadCapabilities(props.assetId)
  try {
    const res = await listFiles(props.assetId, currentPath.value, identity)
    // 載入途中身分又變了：這份結果對應的是舊帳號，丟棄（watcher 會再載一次）
    if (identity !== sessionKey.value) return
    entries.value = res.entries || []
    loadedSessionId.value = identity
  } catch (err) {
    console.error('[FileManager] 讀取目錄失敗:', err?.response?.status, err?.response?.data?.code)
  } finally {
    loading.value = false
  }
}

// 身分變更即作廢畫面（HIGH-1 的核心修法）。
//
// 為何選「重載」而非「連線就緒前禁止開啟檔案管理」：後者只擋得住開檔時機這一種
// 情境，擋不住連線中途身分改變，且會多出一個「按鈕沒反應」的失敗模式；重載是
// 對「清單與操作必須同一身分」這條不變式的直接維護，涵蓋所有觸發來源。
// 先清空 entries 再載入：留著舊清單等於邀請使用者對別的帳號的同路徑按刪除
watch(
  () => sessionKey.value,
  (next, prev) => {
    if (next === prev) return
    entries.value = []
    loadedSessionId.value = undefined
    if (props.modelValue) refresh()
  }
)

// 破壞性／寫入操作的前置閘：清單身分過期就不執行，改為重載並告知。
// watcher 觸發重載與重載完成之間仍有一個 await 視窗，此閘把該視窗關掉
function ensureFreshIdentity() {
  if (!identityStale.value) return true
  ElMessage.warning(t('fileManager.identityChanged'))
  // 已有重載在途就不再疊一次（watcher 通常已觸發），避免連點堆出多筆請求
  if (!loading.value) refresh()
  return false
}

function navigateTo(path) {
  currentPath.value = path
  refresh()
}

function enterDir(row) {
  navigateTo(joinPath(currentPath.value, row.name))
}

function handleRowOpen(row) {
  if (row.is_dir) enterDir(row)
}

async function handleUpload({ file }) {
  if (!ensureFreshIdentity()) return
  try {
    await uploadFile(props.assetId, currentPath.value, file, props.sessionId)
    ElMessage.success(t('fileManager.uploaded', { name: file.name }))
    refresh()
  } catch (err) {
    console.error('[FileManager] 上傳失敗:', err)
  }
}

async function handleDownload(row) {
  if (!ensureFreshIdentity()) return
  try {
    const blob = await downloadFile(props.assetId, joinPath(currentPath.value, row.name), props.sessionId)
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = row.name
    a.click()
    URL.revokeObjectURL(url)
  } catch (err) {
    console.error('[FileManager] 下載失敗:', err)
  }
}

async function handleMkdir() {
  if (!ensureFreshIdentity()) return
  try {
    const { value } = await ElMessageBox.prompt(t('fileManager.mkdirPrompt'), t('fileManager.mkdir'), {
      inputPattern: /^[^/\0]+$/,
      inputErrorMessage: t('fileManager.mkdirInvalid')
    })
    await mkdir(props.assetId, joinPath(currentPath.value, value), props.sessionId)
    ElMessage.success(t('fileManager.mkdirDone'))
    refresh()
  } catch (err) {
    if (err !== 'cancel' && err?.message !== 'cancel') {
      console.error('[FileManager] 建立目錄失敗:', err)
    }
  }
}

async function handleDelete(row) {
  if (!ensureFreshIdentity()) return
  try {
    await ElMessageBox.confirm(
      row.is_dir
        ? t('fileManager.deleteConfirmDir', { name: row.name })
        : t('fileManager.deleteConfirmFile', { name: row.name }),
      t('common.deleteConfirmTitle'),
      {
        confirmButtonText: t('common.deleteConfirmButton'),
        cancelButtonText: t('common.cancel'),
        type: 'warning',
      }
    )
    await deleteFile(props.assetId, joinPath(currentPath.value, row.name), props.sessionId)
    ElMessage.success(t('fileManager.deleted'))
    refresh()
  } catch (err) {
    if (err !== 'cancel') {
      console.error('[FileManager] 刪除失敗:', err)
    }
  }
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

function formatTime(unixSeconds) {
  return new Date(unixSeconds * 1000).toLocaleString(currentLocale(), { hour12: false })
}

// 測試掛點：el-drawer 的 open 事件依賴 transition，測試環境不觸發。
// 下載/建目錄/刪除亦外露，供 D9 的「五端點必帶 session_id」守衛測試逐條驗證
defineExpose({
  refresh,
  navigateTo,
  handleUpload,
  handleDownload,
  handleMkdir,
  handleDelete,
  joinPath,
  // 清單與身分狀態外露供 HIGH-1 的回歸測試斷言「重載前不得操作」
  entries,
  identityStale,
  // 傳輸能力呈現狀態外露供 6.2 的守衛測試（禁止時按鈕不可用、允許時可用）
  canUpload,
  canDownload,
  canDelete,
  deniedFileActions,
})
</script>

<style scoped>
.file-account {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-bottom: 10px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.file-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 12px;
}

.file-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}
</style>
