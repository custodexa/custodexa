<template>
  <div
    v-if="!failed"
    class="mfa-qr"
  >
    <canvas ref="canvasRef" />
  </div>
</template>

<script setup>
// MFA 綁定 QR（mfa-qr-and-button-contrast D-2）：otpauth URL 本地 canvas 渲染，
// secret 不出瀏覽器。白底磁貼＝掃碼器需要亮底深碼（暗色主題下反白是掃碼標準）；
// 渲染失敗靜默隱藏——手輸金鑰路徑不受影響（漸進增強）
import { ref, watch, onMounted } from 'vue'
import QRCode from 'qrcode'

const props = defineProps({
  value: { type: String, required: true },
})

const canvasRef = ref(null)
const failed = ref(false)

const render = async () => {
  if (!props.value || !canvasRef.value) return
  try {
    await QRCode.toCanvas(canvasRef.value, props.value, {
      width: 168,
      margin: 2,
      color: { dark: '#0a1522', light: '#ffffff' },
    })
    failed.value = false
  } catch (error) {
    console.error('QR code 渲染失敗，保留手動輸入路徑:', error)
    failed.value = true
  }
}

onMounted(render)
watch(() => props.value, render)
</script>

<style scoped>
.mfa-qr {
  display: flex;
  justify-content: center;
}

.mfa-qr canvas {
  background: #ffffff;
  border-radius: 8px;
  padding: 4px;
}
</style>
