<template>
  <!-- 取代播放器的說明區塊：白話主句與下一步在第一層，
       會話編號與機器碼收在「給管理員的資訊」裡 -->
  <div
    class="recording-unavailable"
    :class="`is-${state}`"
    role="status"
    data-test="recording-unavailable"
  >
    <div class="recording-unavailable__body">
      <el-icon
        class="recording-unavailable__icon"
        :size="40"
        aria-hidden="true"
      >
        <FileLock v-if="state === 'unreadable'" />
        <FileX v-else />
      </el-icon>
      <div class="recording-unavailable__text">
        <p class="recording-unavailable__title">
          {{ $t(`recordingReadability.card.${state}.title`) }}
        </p>
        <p class="recording-unavailable__desc">
          {{ $t(`recordingReadability.card.${state}.body`) }}
        </p>
        <p class="recording-unavailable__next">
          {{ $t(`recordingReadability.card.${state}.next`) }}
        </p>
        <button
          type="button"
          class="recording-unavailable__toggle"
          :aria-expanded="expanded ? 'true' : 'false'"
          :aria-controls="detailId"
          data-test="recording-admin-toggle"
          @click="expanded = !expanded"
        >
          {{ $t('recordingReadability.adminInfo') }}
          <el-icon :size="12">
            <ChevronDown v-if="expanded" />
            <ChevronRight v-else />
          </el-icon>
        </button>
        <dl
          v-show="expanded"
          :id="detailId"
          class="recording-unavailable__detail"
          data-test="recording-admin-detail"
        >
          <div>
            <dt>{{ $t('recordingReadability.sessionIdLabel') }}</dt>
            <dd>{{ sessionId }}</dd>
          </div>
          <div>
            <dt>{{ $t('recordingReadability.errorCodeLabel') }}</dt>
            <dd>{{ code }}</dd>
          </div>
        </dl>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref, useId } from 'vue'
import { ChevronDown, ChevronRight, FileLock, FileX } from 'lucide-vue-next'
import { codeForState } from '@/utils/recordingReadability'

const props = defineProps({
  // 'unreadable'｜'missing'
  state: { type: String, required: true },
  sessionId: { type: [String, Number], required: true },
})

const expanded = ref(false)
const detailId = `recording-admin-detail-${useId()}`
const code = computed(() => codeForState(props.state))
</script>

<style scoped>
.recording-unavailable {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 300px;
  padding: 32px;
  border-radius: 6px;
  background: var(--ot-terminal-bg);
}

.recording-unavailable__body {
  display: flex;
  gap: 18px;
  align-items: flex-start;
  max-width: 600px;
}

.recording-unavailable__icon {
  flex: none;
}

.is-unreadable .recording-unavailable__icon {
  color: var(--ot-warning);
}

.is-missing .recording-unavailable__icon {
  color: var(--ot-danger);
}

.recording-unavailable__text {
  display: flex;
  flex-direction: column;
  gap: 10px;
  min-width: 0;
}

.recording-unavailable__text p {
  margin: 0;
  line-height: 1.65;
}

.recording-unavailable__title {
  font-size: 17px;
  font-weight: 600;
  line-height: 1.45;
  color: var(--ot-text-primary);
}

.recording-unavailable__desc {
  color: var(--ot-text-primary);
}

.recording-unavailable__next {
  color: var(--ot-text-secondary);
}

.recording-unavailable__toggle {
  display: inline-flex;
  align-self: flex-start;
  align-items: center;
  gap: 4px;
  padding: 0;
  border: 0;
  background: none;
  font: inherit;
  font-size: 13px;
  color: var(--ot-primary);
  cursor: pointer;
}

.recording-unavailable__toggle:hover {
  color: var(--ot-primary-hover);
}

.recording-unavailable__toggle:focus-visible {
  outline: 2px solid var(--ot-primary);
  outline-offset: 2px;
}

.recording-unavailable__detail {
  display: flex;
  flex-direction: column;
  gap: 6px;
  margin: 0;
  padding: 10px 12px;
  border: 1px solid var(--ot-border-subtle);
  border-radius: 6px;
  background: var(--ot-bg-surface);
  font-size: 12px;
}

.recording-unavailable__detail div {
  display: flex;
  gap: 12px;
}

.recording-unavailable__detail dt {
  min-width: 96px;
  color: var(--ot-text-secondary);
}

.recording-unavailable__detail dd {
  margin: 0;
  min-width: 0;
  font-family: var(--ot-font-mono);
  overflow-wrap: anywhere;
}
</style>
