<template>
  <el-drawer
    :model-value="modelValue"
    :title="$t('workspace.commandSnippets')"
    size="380px"
    :append-to-body="true"
    @update:model-value="$emit('update:modelValue', $event)"
    @open="load"
  >
    <div class="snippet-drawer">
      <el-input
        v-model="keyword"
        :placeholder="$t('snippets.searchPlaceholder')"
        clearable
        size="small"
        class="snippet-search"
      />

      <el-empty
        v-if="!filtered.length"
        :description="$t('snippets.empty')"
        :image-size="60"
      />

      <div
        v-for="item in filtered"
        :key="item.id"
        class="snippet-card"
      >
        <div class="snippet-card-header">
          <span class="snippet-name">{{ item.name }}</span>
          <span>
            <el-button
              size="small"
              type="primary"
              link
              @click="$emit('use', item.content)"
            >
              {{ $t('snippets.use') }}
            </el-button>
            <el-button
              size="small"
              type="danger"
              link
              @click="remove(item)"
            >
              {{ $t('common.delete') }}
            </el-button>
          </span>
        </div>
        <pre class="snippet-content">{{ item.content }}</pre>
      </div>

      <el-divider />

      <el-form
        label-position="top"
        size="small"
        @submit.prevent
      >
        <el-form-item :label="$t('common.name')">
          <el-input
            v-model="form.name"
            :placeholder="$t('snippets.namePlaceholder')"
            maxlength="128"
          />
        </el-form-item>
        <el-form-item :label="$t('snippets.contentLabel')">
          <el-input
            v-model="form.content"
            type="textarea"
            :rows="3"
            placeholder="df -h"
            maxlength="4096"
          />
        </el-form-item>
        <el-button
          type="primary"
          size="small"
          :disabled="!form.name || !form.content"
          :loading="saving"
          @click="create"
        >
          {{ $t('snippets.create') }}
        </el-button>
      </el-form>
    </div>
  </el-drawer>
</template>

<script setup>
import { ref, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { getSnippets, createSnippet, deleteSnippet } from '@/api/snippets'
import { t } from '@/i18n'

defineProps({
  modelValue: { type: Boolean, default: false },
})
defineEmits(['update:modelValue', 'use'])

const snippets = ref([])
const keyword = ref('')
const saving = ref(false)
const form = ref({ name: '', content: '' })

const filtered = computed(() => {
  const term = keyword.value.trim().toLowerCase()
  if (!term) return snippets.value
  return snippets.value.filter((s) => s.name.toLowerCase().includes(term))
})

async function load() {
  try {
    const res = await getSnippets()
    snippets.value = res.data || []
  } catch (err) {
    console.error('[SnippetDrawer] 載入片段失敗:', err)
  }
}

async function create() {
  saving.value = true
  try {
    await createSnippet({ name: form.value.name, content: form.value.content })
    form.value = { name: '', content: '' }
    ElMessage.success(t('snippets.created'))
    await load()
  } catch (err) {
    console.error('[SnippetDrawer] 新增片段失敗:', err)
  } finally {
    saving.value = false
  }
}

async function remove(item) {
  try {
    await deleteSnippet(item.id)
    snippets.value = snippets.value.filter((s) => s.id !== item.id)
  } catch (err) {
    console.error('[SnippetDrawer] 刪除片段失敗:', err)
  }
}
</script>

<style scoped>
.snippet-search {
  margin-bottom: 12px;
}

.snippet-card {
  border: 1px solid var(--el-border-color);
  border-radius: 4px;
  padding: 8px 10px;
  margin-bottom: 8px;
}

.snippet-card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.snippet-name {
  font-weight: 600;
  font-size: 13px;
}

.snippet-content {
  margin: 6px 0 0;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
  color: var(--el-text-color-secondary);
  max-height: 96px;
  overflow-y: auto;
}
</style>
