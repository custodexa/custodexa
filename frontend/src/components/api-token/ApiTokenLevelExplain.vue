<template>
  <section
    class="atlx"
    :class="{ 'is-panel': closable }"
    data-test="level-explain"
  >
    <header class="atlx__head">
      <h4 class="atlx__title">
        {{ $t('apiTokens.explain.title') }}
      </h4>
      <button
        v-if="closable"
        type="button"
        class="atlx__close"
        :aria-label="$t('common.close')"
        data-test="level-explain-close"
        @click="emit('close')"
      >
        <X
          :size="14"
          aria-hidden="true"
        />
      </button>
    </header>
    <dl class="atlx__list">
      <dt>
        <el-tag
          size="small"
          type="info"
          class="ot-tag-neutral"
        >
          {{ $t('apiTokens.level.read') }}
        </el-tag>
      </dt>
      <dd>{{ $t('apiTokens.explain.read') }}</dd>
      <dt>
        <el-tag
          size="small"
          type="warning"
        >
          {{ $t('apiTokens.level.read_write') }}
        </el-tag>
      </dt>
      <dd>{{ $t('apiTokens.explain.readWrite') }}</dd>
      <dt class="atlx__plain">
        {{ $t('apiTokens.explain.twoRolesLabel') }}
      </dt>
      <dd>{{ $t('apiTokens.explain.twoRoles') }}</dd>
    </dl>
    <p class="atlx__foot">
      {{ $t('apiTokens.explain.foot') }}
    </p>
  </section>
</template>

<script setup>
import { X } from 'lucide-vue-next'

/**
 * 唯讀與讀寫的說明。建立對話框就地展開（可關閉）與清單「權限」欄頭的提示共用同一段文字。
 */
defineProps({
  closable: { type: Boolean, default: false },
})
const emit = defineEmits(['close'])
</script>

<style scoped>
.atlx {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
  max-width: 440px;
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
}
.atlx.is-panel {
  max-width: none;
  padding: 12px var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  background: var(--ot-bg-page);
}
.atlx__head {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.atlx__title {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-primary);
}
.atlx__close {
  display: inline-flex;
  padding: 2px;
  border: none;
  background: none;
  color: var(--ot-text-secondary);
  cursor: pointer;
}
.atlx__close:focus-visible {
  outline: 2px solid var(--ot-primary);
  outline-offset: 2px;
}
.atlx__list {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 6px 12px;
  margin: 0;
}
.atlx__list dt,
.atlx__list dd {
  margin: 0;
}
.atlx__list dd {
  color: var(--ot-text-primary);
}
.atlx__plain {
  color: var(--ot-text-secondary);
}
.atlx__foot {
  margin: 0;
  color: var(--ot-text-secondary);
}
</style>
