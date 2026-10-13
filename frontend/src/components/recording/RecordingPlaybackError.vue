<template>
  <!-- 播放失敗覆蓋層（文字與圖形播放器共用）。底板不透明：
       蓋在終端畫面或桌面畫面上時，說明文字不得與底下的內容疊字 -->
  <div
    class="recording-playback-error"
    role="alert"
    data-test="recording-playback-error"
  >
    <div class="recording-playback-error__content">
      <el-icon
        :size="32"
        class="recording-playback-error__icon"
        aria-hidden="true"
      >
        <TriangleAlert />
      </el-icon>
      <p class="recording-playback-error__title">
        {{ failure.title }}
      </p>
      <p class="recording-playback-error__detail">
        {{ failure.detail }}
      </p>
      <el-button
        data-test="recording-playback-reload"
        @click="$emit('reload')"
      >
        {{ $t('recordingReadability.playback.reload') }}
      </el-button>
    </div>
  </div>
</template>

<script setup>
import { TriangleAlert } from 'lucide-vue-next'

defineProps({
  // { problem, title, detail }（見 utils/recordingReadability.js 的 playbackFailure）
  failure: { type: Object, required: true },
})
defineEmits(['reload'])
</script>

<style scoped>
.recording-playback-error {
  position: absolute;
  inset: 0;
  z-index: 10;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  background: var(--ot-terminal-bg);
}

.recording-playback-error__content {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 10px;
  max-width: 420px;
  text-align: center;
}

.recording-playback-error__icon {
  color: var(--ot-warning);
}

.recording-playback-error__content p {
  margin: 0;
}

.recording-playback-error__title {
  font-size: 16px;
  font-weight: 600;
  color: var(--ot-text-primary);
}

.recording-playback-error__detail {
  font-size: 13px;
  line-height: 1.65;
  color: var(--ot-text-secondary);
}
</style>
