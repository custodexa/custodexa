<template>
  <Teleport to="body">
    <div
      v-if="visible"
      class="node-move-confirm"
      :class="[`is-${phase}`, `arrow-${pos.side}`]"
      :style="boxStyle"
      role="dialog"
      aria-modal="false"
      :aria-label="title"
    >
      <span
        class="confirm-arrow"
        :style="{ top: `${pos.arrowTop}px` }"
      />
      <div class="confirm-head">
        <span class="confirm-title">{{ title }}</span>
        <button
          v-if="phase !== 'reject'"
          type="button"
          class="confirm-close"
          :disabled="loading"
          :aria-label="$t('common.cancel')"
          @click="$emit('cancel')"
        >
          &times;
        </button>
      </div>

      <dl class="confirm-rows">
        <div class="confirm-row">
          <dt>{{ $t('nodeTree.moveConfirm.node') }}</dt>
          <dd class="strong">
            {{ nodeName }}
          </dd>
        </div>
        <div
          v-if="phase !== 'reject'"
          class="confirm-row"
        >
          <dt>{{ $t('nodeTree.moveConfirm.from') }}</dt>
          <dd>{{ fromPath || $t('nodeTree.allAssets') }}</dd>
        </div>
        <div class="confirm-row">
          <dt>{{ $t('nodeTree.moveConfirm.to') }}</dt>
          <dd>{{ toPath || $t('nodeTree.allAssets') }}</dd>
        </div>
      </dl>

      <div
        v-if="phase === 'reject'"
        class="reject-body"
      >
        <p class="reject-head">
          {{ rejectHead }}
        </p>
        <p class="reject-reason">
          {{ rejectReason }}
        </p>
        <p
          v-if="rejectNext"
          class="reject-next"
        >
          {{ rejectNext }}
        </p>
      </div>
      <div
        v-else
        class="confirm-notes"
      >
        <i18n-t
          keypath="nodeTree.moveConfirm.carry"
          tag="p"
        >
          <template #count>
            <strong>{{ $t('nodeTree.moveConfirm.carryCount', { n: count }) }}</strong>
          </template>
        </i18n-t>
        <p>{{ $t('nodeTree.moveConfirm.authz') }}</p>
        <p>{{ $t('nodeTree.moveConfirm.scope') }}</p>
        <p>{{ $t('nodeTree.moveConfirm.direct') }}</p>
      </div>

      <div class="confirm-actions">
        <template v-if="phase === 'reject'">
          <el-button
            type="primary"
            class="btn-got-it"
            @click="$emit('ack')"
          >
            {{ $t('nodeTree.moveConfirm.gotIt') }}
          </el-button>
        </template>
        <template v-else>
          <el-button
            class="btn-cancel"
            :disabled="loading"
            @click="$emit('cancel')"
          >
            {{ $t('common.cancel') }}
          </el-button>
          <el-button
            type="primary"
            class="btn-ok"
            :loading="loading"
            :disabled="loading"
            @click="$emit('confirm')"
          >
            {{ loading ? $t('nodeTree.moveConfirm.moving') : $t('nodeTree.moveConfirm.ok') }}
          </el-button>
        </template>
      </div>
    </div>
  </Teleport>
</template>

<script setup>
import { computed, watch, onBeforeUnmount } from 'vue'
import { t } from '@/i18n'
import { placeConfirm } from '@/composables/useNodeTreeDrag'

const props = defineProps({
  visible: { type: Boolean, default: false },
  // confirm＝等待確認；moving＝處理中；reject＝被拒或無法確認的說明
  phase: { type: String, default: 'confirm' },
  nodeName: { type: String, default: '' },
  fromPath: { type: String, default: '' },
  toPath: { type: String, default: '' },
  count: { type: Number, default: 0 },
  // 目標列的視窗座標矩形 { top, bottom, left, right }；沒有時置中
  anchor: { type: Object, default: null },
  rejectHead: { type: String, default: '' },
  rejectReason: { type: String, default: '' },
  rejectNext: { type: String, default: '' },
})
const emit = defineEmits(['confirm', 'cancel', 'ack'])

const loading = computed(() => props.phase === 'moving')
const title = computed(() =>
  props.phase === 'reject' ? t('nodeTree.moveConfirm.rejectTitle') : t('nodeTree.moveConfirm.title')
)

const pos = computed(() => {
  const viewport = { width: window.innerWidth, height: window.innerHeight }
  if (props.anchor) return placeConfirm({ row: props.anchor, viewport })
  return {
    left: Math.max(8, (viewport.width - 360) / 2),
    top: Math.max(8, viewport.height / 4),
    side: 'right',
    arrowTop: -100,
  }
})
const boxStyle = computed(() => ({ left: `${pos.value.left}px`, top: `${pos.value.top}px` }))

// Esc：確認階段＝取消；說明階段＝知道了；處理中不處理
const onKey = (e) => {
  if (e.key !== 'Escape') return
  if (props.phase === 'confirm') emit('cancel')
  else if (props.phase === 'reject') emit('ack')
}
watch(
  () => props.visible,
  (on) => {
    if (on) document.addEventListener('keydown', onKey)
    else document.removeEventListener('keydown', onKey)
  },
  { immediate: true }
)
onBeforeUnmount(() => document.removeEventListener('keydown', onKey))
</script>

<style scoped>
.node-move-confirm {
  position: fixed;
  z-index: 3000;
  width: 360px;
  box-sizing: border-box;
  padding: var(--ot-space-md, 16px);
  background: var(--el-bg-color-overlay, #fff);
  border: 1px solid var(--ot-border-subtle, #e4e7ed);
  border-radius: 8px;
  box-shadow: var(--el-box-shadow-light, 0 4px 16px rgba(0, 0, 0, 0.15));
}

.confirm-arrow {
  position: absolute;
  width: 10px;
  height: 10px;
  margin-top: -5px;
  background: inherit;
  border: 1px solid var(--ot-border-subtle, #e4e7ed);
  transform: rotate(45deg);
}

.arrow-right .confirm-arrow {
  left: -6px;
  border-right: 0;
  border-top: 0;
}

.arrow-left .confirm-arrow {
  right: -6px;
  border-left: 0;
  border-bottom: 0;
}

.confirm-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
}

.confirm-title {
  font-weight: 600;
  color: var(--ot-text-primary);
}

.confirm-close {
  border: 0;
  background: transparent;
  font-size: 18px;
  line-height: 1;
  cursor: pointer;
  color: var(--ot-text-secondary);
}

.confirm-close:disabled {
  cursor: not-allowed;
  opacity: 0.4;
}

.confirm-rows {
  margin: 0 0 8px;
}

.confirm-row {
  display: flex;
  gap: 8px;
  padding: 2px 0;
  font-size: 13px;
}

.confirm-row dt {
  flex: 0 0 56px;
  color: var(--ot-text-secondary);
}

.confirm-row dd {
  margin: 0;
  min-width: 0;
  word-break: break-all;
}

.confirm-row dd.strong {
  font-weight: 600;
}

.confirm-notes p,
.reject-body p {
  margin: 4px 0;
  font-size: 12.5px;
  line-height: 1.6;
  color: var(--ot-text-secondary);
}

.reject-body .reject-head {
  font-weight: 600;
  color: var(--el-color-danger);
}

.reject-body {
  padding: 8px;
  border-radius: 4px;
  background: var(--el-color-danger-light-9);
}

.reject-body .reject-reason {
  color: var(--el-color-danger);
}

.confirm-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  margin-top: 12px;
}
</style>
