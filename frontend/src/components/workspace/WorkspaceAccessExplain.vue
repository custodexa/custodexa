<template>
  <!-- 受限資產的點擊說明：不發簽發，只說原因與下一步；
       需審核者附「前往資產頁申請」，本頁不內嵌申請表單 -->
  <div
    ref="rootRef"
    class="access-explain"
    role="dialog"
    aria-labelledby="access-explain-title"
    tabindex="-1"
    :data-state="state"
    :style="{ top: top + 'px', left: left + 'px' }"
    data-test="access-explain"
  >
    <button
      type="button"
      class="access-explain__close"
      :aria-label="$t('workspace.explainClose')"
      @click="emit('close')"
    >
      ×
    </button>
    <div
      id="access-explain-title"
      class="access-explain__title"
    >
      {{ $t(EXPLAIN_TEXT[state].title) }}
    </div>
    <p class="access-explain__body">
      {{ $t(EXPLAIN_TEXT[state].body) }}
    </p>
    <el-button
      v-if="state === 'approval'"
      type="primary"
      size="small"
      data-test="go-apply"
      @click="emit('apply')"
    >
      {{ $t('workspace.goApply') }}
    </el-button>
  </div>
</template>

<script setup>
import { ref } from 'vue'

defineProps({
  // 受限三態之一：view_only／pending／approval
  state: {
    type: String,
    required: true,
    validator: (v) => ['view_only', 'pending', 'approval'].includes(v),
  },
  top: { type: Number, default: 0 },
  left: { type: Number, default: 0 },
})

const emit = defineEmits(['close', 'apply'])

const EXPLAIN_TEXT = {
  view_only: { title: 'workspace.explainViewOnlyTitle', body: 'workspace.explainViewOnlyBody' },
  pending: { title: 'workspace.explainPendingTitle', body: 'workspace.explainPendingBody' },
  approval: { title: 'workspace.explainApprovalTitle', body: 'workspace.explainApprovalBody' },
}

const rootRef = ref(null)

// contains：供外層的「點外部即關閉」判斷點擊是否落在說明框內
defineExpose({
  focus: () => rootRef.value?.focus?.(),
  contains: (node) => !!rootRef.value?.contains?.(node),
})
</script>

<style scoped>
/* 貼在該列右側 */
.access-explain {
  position: fixed;
  z-index: 2500;
  width: 300px;
  padding: 12px 14px;
  border: 1px solid var(--ot-border);
  border-radius: var(--ot-radius-md);
  background: var(--ot-bg-elevated);
  box-shadow: var(--ot-shadow-md);
  color: var(--ot-text-primary);
}

.access-explain:focus {
  outline: none;
}

.access-explain__close {
  position: absolute;
  top: 6px;
  right: 8px;
  border: none;
  background: transparent;
  color: var(--ot-text-secondary);
  cursor: pointer;
  font-size: 16px;
  line-height: 1;
}

.access-explain__title {
  margin-right: 16px;
  font-size: 14px;
  font-weight: 600;
}

.access-explain__body {
  margin: 6px 0 0;
  font-size: 13px;
  line-height: 1.6;
  color: var(--ot-text-secondary);
}

.access-explain .el-button {
  margin-top: 10px;
}
</style>
