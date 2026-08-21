<template>
  <div
    v-if="backgroundImage"
    class="terminal-watermark"
    :style="{ backgroundImage }"
  />
</template>

<script setup>
import { ref, onMounted } from 'vue'

// 會話浮水印（session-watermark）：
// canvas 旋轉文字→dataURL 平鋪；pointer-events none 不擋輸入；canvas 不可用靜默降級
const props = defineProps({
  content: { type: String, default: '' },
})

const backgroundImage = ref('')

function buildWatermark() {
  const user = JSON.parse(localStorage.getItem('user') || '{}')
  const date = new Date().toISOString().slice(0, 10)
  const text = props.content || `${user.username || ''} ${date}`.trim()
  if (!text) return

  try {
    const canvas = document.createElement('canvas')
    canvas.width = 360
    canvas.height = 240
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    ctx.translate(canvas.width / 2, canvas.height / 2)
    ctx.rotate((-20 * Math.PI) / 180)
    ctx.font = '14px sans-serif'
    ctx.fillStyle = 'rgba(128, 128, 128, 0.12)'
    ctx.textAlign = 'center'
    ctx.fillText(text, 0, 0)

    backgroundImage.value = `url('${canvas.toDataURL()}')`
  } catch (err) {
    // happy-dom / 受限環境無 canvas：靜默省略，不影響會話
    console.warn('[Watermark] canvas 不可用，略過浮水印:', err?.message)
  }
}

onMounted(buildWatermark)
</script>

<style scoped>
.terminal-watermark {
  position: absolute;
  inset: 0;
  z-index: 9;
  pointer-events: none;
  background-repeat: repeat;
}
</style>
