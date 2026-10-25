<template>
  <!-- 刪除節點被管理範圍引用而被擋：超級管理者看到逐筆引用與修改入口，
       其他持有者只看到筆數（不列名），引導聯絡能調整指派的人 -->
  <el-dialog
    :model-value="modelValue"
    :title="$t('nodeTree.deleteBlocked.title')"
    width="480px"
    append-to-body
    @update:model-value="(v) => emit('update:modelValue', v)"
  >
    <template v-if="detailed">
      <p class="blocked-body">
        {{ $t('nodeTree.deleteBlocked.superBody', { path, count }) }}
      </p>
      <div class="blocked-list-title">
        {{ $t('nodeTree.deleteBlocked.listTitle') }}
      </div>
      <ul class="blocked-list">
        <li
          v-for="(ref, idx) in references"
          :key="`${ref.subject_kind}-${ref.subject_id}-${ref.role_id}-${idx}`"
          class="blocked-item"
        >
          <span class="blocked-subject">{{ ref.subject_name }}</span>
          <span class="blocked-role">{{ ref.role_name }}</span>
          <span
            v-if="ref.subject_kind === 'user_group' && ref.member_count != null"
            class="blocked-members"
          >{{ $t('nodeTree.deleteBlocked.groupMembers', { count: ref.member_count }) }}</span>
          <el-button
            link
            type="primary"
            size="small"
            class="blocked-go"
            :disabled="!editPath(ref)"
            @click="goEdit(ref)"
          >
            {{ $t('nodeTree.deleteBlocked.goEdit') }}
          </el-button>
        </li>
      </ul>
    </template>
    <template v-else>
      <p class="blocked-body">
        {{ $t('nodeTree.deleteBlocked.scopedBody', { path, count }) }}
      </p>
      <p class="blocked-hint">
        {{ $t('nodeTree.deleteBlocked.scopedHint') }}
      </p>
    </template>
    <template #footer>
      <el-button @click="emit('update:modelValue', false)">
        {{ $t('common.close') }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { computed } from 'vue'
import { useRouter } from 'vue-router'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  // 節點路徑與引用筆數取自錯誤回應的 params
  path: { type: String, default: '' },
  count: { type: Number, default: 0 },
  // 只有超級管理者的回應帶 references；其他持有者為 null
  references: { type: Array, default: null },
})
const emit = defineEmits(['update:modelValue'])

// 未安裝 router 時為 undefined，「前往修改」不動作
const router = useRouter() ?? null
const detailed = computed(() => Array.isArray(props.references))

// 指派的編輯入口：使用者與使用者群組詳情頁的「角色與範圍」分頁
const editPath = (ref) => {
  if (ref.subject_kind === 'user') return `/users/${ref.subject_id}?tab=roles`
  if (ref.subject_kind === 'user_group') return `/user-groups/${ref.subject_id}?tab=roles`
  return ''
}
const goEdit = (ref) => {
  const target = editPath(ref)
  if (!target || !router) return
  emit('update:modelValue', false)
  router.push(target)
}
</script>

<style scoped>
.blocked-body {
  margin: 0 0 var(--ot-space-sm);
  color: var(--ot-text-primary);
}

.blocked-hint {
  margin: 0;
  color: var(--ot-text-secondary);
  font-size: 13px;
}

.blocked-list-title {
  font-size: 12px;
  color: var(--ot-text-secondary);
  margin-bottom: var(--ot-space-xs);
}

.blocked-list {
  list-style: none;
  margin: 0;
  padding: 0;
  max-height: 280px;
  overflow-y: auto;
}

.blocked-item {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  padding: 6px 0;
  border-bottom: 1px solid var(--ot-border-subtle);
}

.blocked-subject {
  font-weight: 600;
  color: var(--ot-text-primary);
}

.blocked-role,
.blocked-members {
  color: var(--ot-text-secondary);
  font-size: 12px;
}

.blocked-go {
  margin-left: auto;
}
</style>
