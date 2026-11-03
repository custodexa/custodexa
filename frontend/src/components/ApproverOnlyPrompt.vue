<template>
  <div
    class="approver-only-prompt"
    role="alert"
  >
    <strong
      class="prompt-title"
      data-test="approver-only-title"
    >{{ text.title }}</strong>
    <p class="prompt-body">
      {{ text.body }}
    </p>
    <slot />
    <div
      v-if="text.fix || showCancel"
      class="prompt-actions"
    >
      <el-button
        v-if="showCancel"
        size="small"
        :disabled="loading"
        data-test="approver-only-cancel"
        @click="$emit('cancel')"
      >
        {{ $t('common.cancel') }}
      </el-button>
      <el-button
        v-if="text.fix"
        type="primary"
        size="small"
        :loading="loading"
        data-test="approver-only-fix"
        @click="$emit('fix')"
      >
        {{ text.fix }}
      </el-button>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { t } from '@/i18n'

/**
 * 「只有審核者角色」的就近說明框：放在剛按下的儲存鈕或剛改的欄位正下方。
 * 修正鈕是唯一往前走的按鈕（主要樣式）；沒有修正鈕時只顯示說明與插槽內容（例如前往連結）。
 * 文案以 copy（i18n 鍵 { title, body, fix? }）給定。
 */
const props = defineProps({
  copy: { type: Object, required: true },
  showCancel: { type: Boolean, default: false },
  loading: { type: Boolean, default: false },
})
defineEmits(['fix', 'cancel'])

const text = computed(() => ({
  title: t(props.copy.title),
  body: t(props.copy.body),
  fix: props.copy.fix ? t(props.copy.fix) : '',
}))
</script>

<style scoped>
.approver-only-prompt {
  margin-top: var(--ot-space-sm);
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--ot-warning);
  border-radius: var(--ot-radius-md);
  background: var(--ot-bg-hover);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
  text-align: left;
}
.prompt-title {
  display: block;
  color: var(--ot-text-primary);
}
.prompt-body {
  margin: var(--ot-space-xs) 0 0;
  line-height: 1.6;
}
.prompt-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--ot-space-sm);
  margin-top: var(--ot-space-sm);
}
</style>
