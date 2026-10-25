<template>
  <p class="readonly-note">
    <Eye
      :size="14"
      aria-hidden="true"
    />
    <span><slot /></span>
  </p>
</template>

<script setup>
import { Eye } from 'lucide-vue-next'
</script>

<style scoped>
/* 緊接頁首副標下方的一行灰字：PageHeader 自帶 lg 下距，這裡往上收回，只留 6px */
.readonly-note {
  display: flex;
  align-items: center;
  gap: 6px;
  margin: calc(6px - var(--ot-space-lg)) 0 var(--ot-space-md);
  font-size: 13px;
  line-height: 1.6;
  color: var(--ot-text-disabled);
}

.readonly-note svg {
  flex: none;
}
</style>
