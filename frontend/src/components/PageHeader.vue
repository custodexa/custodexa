<template>
  <div class="page-header">
    <div class="page-header-text">
      <h1 class="page-title">
        {{ title }}
        <el-tag
          v-if="previewReadOnly"
          size="small"
          type="info"
          class="preview-readonly-tag"
          data-test="preview-readonly-tag"
        >
          {{ $t('roles.state.read') }}
        </el-tag>
        <el-tag
          v-else-if="tag"
          size="small"
          type="info"
          class="preview-readonly-tag"
          data-test="page-header-tag"
        >
          {{ tag }}
        </el-tag>
      </h1>
      <p
        v-if="description"
        class="page-description"
      >
        {{ description }}
      </p>
      <p
        v-if="previewReadOnly && !ownReadonlyNote"
        class="page-description preview-readonly-note"
        data-test="preview-readonly-note"
      >
        {{ $t('rolePreview.readOnlyNote') }}
      </p>
      <div
        v-if="$slots.meta"
        class="page-meta"
      >
        <slot name="meta" />
      </div>
    </div>
    <div class="page-actions">
      <slot name="actions" />
    </div>
  </div>
</template>

<script setup>
import { computed, getCurrentInstance } from 'vue'
import { previewPageState } from '@/composables/useRolePreview'

defineProps({
  title: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    default: '',
  },
  // 標題旁的狀態標籤（例如唯讀）；預覽中的唯讀標籤優先
  tag: {
    type: String,
    default: '',
  },
  // 頁面已有自己的唯讀說明時為真：預覽中沿用該說明，不再加通用句
  ownReadonlyNote: {
    type: Boolean,
    default: false,
  },
})

// 以此角色預覽：目前頁在預覽集合的頁面狀態為唯讀時，標題旁標示並說明。
// 路由取自 app 的 $route（未安裝路由的單元測試中為空，視為非唯讀），
// 不 import vue-router，避免替身未提供該匯出的測試受影響。
const route = getCurrentInstance()?.appContext.config.globalProperties.$route
const previewReadOnly = computed(() => previewPageState(route?.path) === 'read')
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

.preview-readonly-tag {
  margin-left: var(--ot-space-xs);
  vertical-align: middle;
}

.preview-readonly-note {
  color: var(--ot-text-disabled);
}

.page-meta {
  margin-top: var(--ot-space-xs);
}

.page-actions {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  flex-shrink: 0;
}
</style>
