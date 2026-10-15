<template>
  <!-- 會話工具：置於頁籤列右端既有空白，
       操作目前啟用文字終端會話；檔案/監控為 SSH 專屬能力 -->
  <div
    ref="rootRef"
    class="tabbar-tools"
  >
    <!-- K8s 連線 context（解決「看不出在哪個 ns/pod/container」）-->
    <span
      v-if="tab.protocol === 'k8s'"
      class="k8s-ctx"
    >
      <span class="k8s-ctx__seg"><b>ns</b> {{ tab.k8sNamespace }}</span>
      <span class="k8s-ctx__seg"><b>pod</b> {{ tab.k8sPod }}</span>
      <span
        v-if="tab.k8sContainer"
        class="k8s-ctx__seg"
      ><b>ctr</b> {{ tab.k8sContainer }}</span>
      <span
        class="k8s-ctx__badge"
        :class="tab.k8sMode === 'logs' ? 'is-logs' : 'is-exec'"
      >{{ tab.k8sMode === 'logs' ? $t('workspace.k8sLogsReadonly') : 'exec' }}</span>
    </span>
    <el-tooltip :content="$t('workspace.shareSession')">
      <button
        type="button"
        class="tool-btn"
        :aria-label="$t('workspace.shareSession')"
        @click="emit('open-panel', 'share')"
      >
        <el-icon><Share2 /></el-icon>
      </button>
    </el-tooltip>
    <el-tooltip
      v-if="tab.protocol === 'ssh'"
      :content="$t('workspace.fileManager')"
    >
      <button
        type="button"
        class="tool-btn"
        :aria-label="$t('workspace.fileManager')"
        @click="emit('open-panel', 'file')"
      >
        <el-icon><FolderOpen /></el-icon>
      </button>
    </el-tooltip>
    <el-tooltip
      v-if="tab.protocol === 'ssh'"
      :content="$t('workspace.systemMonitor')"
    >
      <button
        type="button"
        class="tool-btn"
        :aria-label="$t('workspace.systemMonitor')"
        @click="emit('open-panel', 'stats')"
      >
        <el-icon><Activity /></el-icon>
      </button>
    </el-tooltip>
    <el-tooltip :content="$t('workspace.commandSnippets')">
      <button
        type="button"
        class="tool-btn"
        :aria-label="$t('workspace.commandSnippets')"
        @click="emit('open-panel', 'snippet')"
      >
        <el-icon><FileCode /></el-icon>
      </button>
    </el-tooltip>
    <el-tooltip
      v-if="tab.protocol === 'k8s' && tab.k8sMode !== 'logs'"
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
      v-if="tab.protocol === 'k8s' && tab.k8sMode !== 'logs'"
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
    <input
      ref="k8sFileInput"
      type="file"
      style="display: none"
      @change="onK8sFileChange"
    >
  </div>
</template>

<script setup>
import { ref, onMounted, onBeforeUnmount } from 'vue'
import { Share2, FolderOpen, Activity, FileCode, Upload, Download } from 'lucide-vue-next'
import { ElMessage, ElMessageBox } from 'element-plus'
import { t } from '@/i18n'
import { uploadK8sFile, downloadK8sFile } from '@/api/assets'
import { resolveApiError } from '@/api/error'

const props = defineProps({
  // 目前啟用的文字終端分頁（主控台分頁不適用這組工具）
  tab: { type: Object, required: true },
})

// open-panel：'share'／'file'／'stats'／'snippet'，由外層打開該分頁的對應面板；
// width：工具列實測寬度，外層據以在分頁列右側預留空間
const emit = defineEmits(['open-panel', 'width'])

// 量工具列實際寬度回報外層，分頁不再被它蓋住
const rootRef = ref(null)
let observer = null

onMounted(() => {
  const el = rootRef.value
  if (!el) return
  emit('width', Math.ceil(el.getBoundingClientRect?.().width || 0))
  if (typeof ResizeObserver === 'undefined') return
  observer = new ResizeObserver((entries) => {
    const entry = entries[entries.length - 1]
    if (entry) emit('width', Math.ceil(entry.contentRect.width))
  })
  observer.observe(el)
})

onBeforeUnmount(() => {
  observer?.disconnect()
  observer = null
  emit('width', 0)
})

// K8s 容器檔案上傳（kubectl cp）：傳到容器 /tmp
const k8sFileInput = ref(null)
function triggerK8sUpload() {
  if (k8sFileInput.value) k8sFileInput.value.click()
}
async function onK8sFileChange(e) {
  const file = e.target.files && e.target.files[0]
  const tab = props.tab
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
  const tab = props.tab
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
</script>

<style scoped>
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
</style>
