<template>
  <div class="page-header">
    <div class="page-header-text">
      <h1 class="page-title">
        {{ title }}
      </h1>
      <p
        v-if="description"
        class="page-description"
      >
        {{ description }}
      </p>
    </div>
    <div class="page-actions">
      <slot name="actions" />
    </div>
  </div>
</template>

<script setup>
defineProps({
  title: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    default: '',
  },
})
</script>

<style scoped>
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--ot-space-lg);
  gap: var(--ot-space-md);
}

.page-title {
  font-size: var(--ot-font-size-xl);
  font-weight: 600;
  color: var(--ot-text-primary);
  margin: 0;
  line-height: 1.4;
}

.page-description {
  margin: var(--ot-space-xs) 0 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.page-actions {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  flex-shrink: 0;
}
</style>
