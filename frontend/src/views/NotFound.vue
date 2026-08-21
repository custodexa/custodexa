<template>
  <div class="not-found">
    <div class="not-found-content">
      <p class="not-found-code">
        404
      </p>
      <p class="not-found-title">
        {{ $t('notFound.title') }}
      </p>
      <p class="not-found-hint">
        {{ $t('notFound.hint') }}
      </p>
      <el-button
        type="primary"
        @click="goHome"
      >
        {{ $t('notFound.backHome') }}
      </el-button>
    </div>
  </div>
</template>

<script setup>
import { useRouter } from 'vue-router'

const router = useRouter()

const goHome = () => {
  router.push('/dashboard')
}
</script>

<style scoped>
.not-found {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  background: var(--ot-bg-page);
}

.not-found-content {
  text-align: center;
  padding: var(--ot-space-xl);
}

.not-found-code {
  font-size: 96px;
  font-weight: 700;
  color: var(--ot-text-disabled);
  margin: 0 0 var(--ot-space-md) 0;
  line-height: 1;
  letter-spacing: -2px;
}

.not-found-title {
  font-size: var(--ot-font-size-xl);
  font-weight: 600;
  color: var(--ot-text-primary);
  margin: 0 0 var(--ot-space-sm) 0;
}

.not-found-hint {
  font-size: var(--ot-font-size-md);
  color: var(--ot-text-secondary);
  margin: 0 0 var(--ot-space-lg) 0;
}
</style>
