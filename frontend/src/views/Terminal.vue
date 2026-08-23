<template>
  <div
    class="terminal-page"
    :style="{ background: pageBackground }"
  >
    <!-- 載入中狀態 -->
    <div
      v-if="loading"
      class="loading-container"
    >
      <el-icon
        class="is-loading"
        :size="40"
      >
        <Loading />
      </el-icon>
      <p>{{ $t('terminal.loading') }}</p>
    </div>

    <!-- 錯誤狀態 -->
    <div
      v-else-if="error"
      class="error-container"
    >
      <el-result
        icon="error"
        :title="$t('terminal.loadFailedTitle')"
        :sub-title="error"
      >
        <template #extra>
          <el-button
            type="primary"
            @click="$router.push('/assets')"
          >
            {{ $t('terminal.backToAssets') }}
          </el-button>
        </template>
      </el-result>
    </div>

    <!-- 連線介面：40px 細頂欄（terminal-navigation）+ 內容區 -->
    <template v-else-if="asset">
      <div class="session-header">
        <el-link
          class="brand-link"
          :underline="false"
          @click="openSystem"
        >
          {{ BRAND.name }}
        </el-link>
        <el-divider direction="vertical" />
        <span class="asset-name">{{ asset.name }}</span>
        <el-tag
          size="small"
          :type="asset.protocol === 'ssh' ? 'success' : isTextTerminal(asset.protocol) ? 'warning' : 'primary'"
        >
          {{ asset.protocol.toUpperCase() }}
        </el-tag>
        <div class="header-actions">
          <el-button
            v-if="asset.protocol === 'ssh'"
            size="small"
            @click="fileManagerVisible = true"
          >
            {{ $t('terminal.files') }}
          </el-button>
        </div>
      </div>

      <div class="session-content">
        <!-- 文字終端類（SSH 與資料庫 CLI）：原生 xterm.js 直連，只傳 assetId，憑證由後端注入 -->
        <template v-if="isTextTerminal(asset.protocol)">
          <SshTerminal
            :asset-id="assetId"
            :protocol="asset.protocol"
          />
          <FileManager
            v-if="asset.protocol === 'ssh'"
            v-model="fileManagerVisible"
            :asset-id="assetId"
          />
        </template>

        <!-- RDP/VNC：guacd 圖形協議路徑（同樣只傳資產參照，憑證後端注入） -->
        <GuacamoleClient
          v-else
          :asset-id="assetId"
          :protocol="asset.protocol"
          :asset-name="asset.name"
        />
      </div>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { BRAND } from '@/brand'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Loading } from '@element-plus/icons-vue'
import GuacamoleClient from '@/components/GuacamoleClient.vue'
import SshTerminal from '@/components/SshTerminal.vue'
import FileManager from '@/components/FileManager.vue'
import { getAsset } from '@/api/assets'
import { isTextTerminal } from '@/utils/protocol'
import { TERMINAL_BACKGROUND } from '@/styles/terminal-theme'
import { t } from '@/i18n'

const route = useRoute()

const assetId = route.params.assetId
const loading = ref(true)
const error = ref(null)
const asset = ref(null)
const fileManagerVisible = ref(false)

// 回系統開新分頁：服務直接輸入 URL 進來的使用者，另開分頁而非跳轉，會話因此不被銷毀
const openSystem = () => {
  window.open('/', '_blank')
}

// 動態背景色：文字終端使用深色背景，RDP 使用白色托住 Canvas
// RDP 的 Canvas 使用 z-index: -1 (Guacamole 官方設計)，需要非透明背景才能正確顯示
const pageBackground = computed(() => {
  if (!asset.value) return TERMINAL_BACKGROUND
  return isTextTerminal(asset.value.protocol) ? TERMINAL_BACKGROUND : '#ffffff'
})

onMounted(async () => {
  await fetchAssetInfo()
})

// 獲取資產資訊
const fetchAssetInfo = async () => {
  try {
    loading.value = true
    error.value = null

    console.log('[Terminal] 載入資產 ID:', assetId)

    // 連線收口：全協議只取基本資產資訊（無憑證），憑證由後端於連線時注入
    asset.value = await getAsset(assetId)

    if (!asset.value.has_password && !asset.value.has_private_key) {
      ElMessage.warning(t('terminal.noCredentialWarning'))
    }

  } catch (err) {
    console.error('[Terminal] 載入資產失敗:', err)

    if (err.response?.status === 404) {
      error.value = t('terminal.assetNotFound')
    } else if (err.response?.status === 403) {
      error.value = t('terminal.noPermission')
    } else {
      error.value = err.message || t('terminal.loadFailed')
    }

  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.terminal-page {
  display: flex;
  flex-direction: column;
  width: 100%;
  height: 100vh;
  /* 背景色由 :style 動態設定（SSH: terminal token, RDP: white） */
  overflow: hidden;
  /* 創建 Stacking Context 以托住 Guacamole Canvas (z-index: -1) */
  /* 這確保 RDP 的 Canvas 不會渲染到父容器背景之後 */
  position: relative;
  z-index: 0;
}

.session-header {
  display: flex;
  align-items: center;
  gap: 10px;
  height: 40px;
  padding: 0 14px;
  flex-shrink: 0;
  background: #1c2128;
  border-bottom: 1px solid #30363d;
  color: var(--ot-terminal-fg, #e6edf3);
}

.brand-link {
  font-weight: 600;
  color: var(--ot-terminal-fg, #e6edf3);
}

.asset-name {
  font-size: 13px;
  opacity: 0.85;
}

.header-actions {
  margin-left: auto;
}

.session-content {
  flex: 1;
  min-height: 0;
  position: relative;
}

.loading-container,
.error-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100vh;
  background: var(--ot-terminal-bg);
  color: var(--ot-text-primary);
}

.loading-container p {
  margin-top: 20px;
  font-size: 16px;
  color: var(--ot-text-secondary);
}

.error-container {
  padding: 40px;
}
</style>
