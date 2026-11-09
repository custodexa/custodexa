<!--
  ExecutorPublicKeyPanel：專用帳號公鑰的取得、複製與下載。

  兩種用法：inline（對話框結果內嵌，掛載即取得）與錨定彈出框（anchor 為觸發元素，
  每次打開重新取得）。每次取得都會留審計，所以不快取。公鑰只來自匯出回應，
  讀取專用帳號的回應不帶公鑰。彈出框打開時焦點移到標題；按「關閉」或 Esc 只關
  彈出框（不連外層抽屜），焦點回到觸發的按鈕。
-->
<template>
  <div
    v-if="inline"
    class="pk-body"
    data-test="executor-public-key-inline"
  >
    <ExecutorPublicKeyBody
      inline
      :text="text"
      :loading="loading"
      :error="error"
      :account="account"
      :fingerprint="fingerprint"
      @copy="copyKey"
      @download="downloadKey"
      @copy-fingerprint="copyFingerprint"
    />
  </div>
  <el-popover
    v-else
    :visible="visible"
    :virtual-ref="anchor || undefined"
    virtual-triggering
    placement="bottom-start"
    :width="440"
    :teleported="false"
    trigger="click"
    @hide="emit('update:visible', false)"
    @after-leave="onAfterLeave"
  >
    <div
      class="pk-body"
      data-test="executor-public-key-popover"
    >
      <ExecutorPublicKeyBody
        ref="bodyRef"
        :text="text"
        :loading="loading"
        :error="error"
        :account="account"
        @copy="copyKey"
        @download="downloadKey"
      />
      <el-button
        link
        size="small"
        class="pk-close"
        data-test="executor-public-key-close"
        @click="close"
      >
        {{ t('common.close') }}
      </el-button>
    </div>
  </el-popover>
</template>

<script setup>
import { nextTick, onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { useI18n } from 'vue-i18n'
import { exportAssetExecutorPublicKey } from '@/api/assetExecutor'
import { resolveApiError } from '@/api/error'
import { useEscapeToClose } from '@/composables/useEscapeToClose'
import ExecutorPublicKeyBody from '@/components/asset/ExecutorPublicKeyBody.vue'

const props = defineProps({
  assetId: { type: [Number, String], required: true },
  account: { type: String, default: '' },
  // 內嵌（設定結果）才顯示指紋列；彈出框的指紋已在區塊資訊列
  fingerprint: { type: String, default: '' },
  inline: { type: Boolean, default: false },
  visible: { type: Boolean, default: false },
  anchor: { type: Object, default: null },
})
const emit = defineEmits(['update:visible', 'unavailable'])

const { t } = useI18n()
const text = ref('')
const loading = ref(false)
const error = ref('')
const bodyRef = ref(null)

async function fetchKey() {
  loading.value = true
  error.value = ''
  text.value = ''
  try {
    const res = await exportAssetExecutorPublicKey(props.assetId)
    text.value = String(res || '').trim()
  } catch (err) {
    if (err?.response?.status === 404) {
      error.value = t('assetExecutor.publicKey.unavailable')
      emit('unavailable')
    } else {
      error.value = resolveApiError(err?.response?.data, err?.response?.status, t('common.unknownError'))
    }
  } finally {
    loading.value = false
  }
}

async function writeClipboard(value, okKey) {
  try {
    await navigator.clipboard.writeText(value)
    ElMessage.success(t(okKey))
  } catch {
    ElMessage.error(t('common.copyFailed'))
  }
}
const copyKey = () => writeClipboard(text.value, 'assetExecutor.publicKey.copied')
const copyFingerprint = () => writeClipboard(props.fingerprint, 'assetExecutor.fingerprintCopied')

function downloadKey() {
  const blob = new Blob([`${text.value}\n`], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${props.account}.pub`
  a.click()
  URL.revokeObjectURL(url)
}

// 使用者關閉（「關閉」鈕或 Esc）：只關彈出框，焦點回到觸發的按鈕
// 彈出框收起時元件庫會把焦點還給打開前的元素；若那是 body，收起後再補一次
let returnFocus = false
function close() {
  returnFocus = true
  emit('update:visible', false)
  props.anchor?.focus?.()
}
function onAfterLeave() {
  const active = document.activeElement
  if (returnFocus && (!active || active === document.body)) props.anchor?.focus?.()
  returnFocus = false
}
useEscapeToClose(() => !props.inline && props.visible, close)

// 每次打開都重新取得（每次取得都留審計）；焦點移到標題，鍵盤使用者從彈出框開始
watch(() => props.visible, async (v) => {
  if (!v) {
    text.value = ''
    return
  }
  if (props.inline) return
  void fetchKey()
  await nextTick()
  bodyRef.value?.titleRef?.focus?.()
})
onMounted(() => {
  if (props.inline) void fetchKey()
})

defineExpose({ text, fetchKey, downloadKey, close })
</script>

<style scoped>
.pk-body {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
}

.pk-close {
  align-self: flex-end;
}
</style>
