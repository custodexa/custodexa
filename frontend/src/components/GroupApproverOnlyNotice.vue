<template>
  <div
    class="group-approver-only"
    role="alert"
    data-test="group-approver-only"
  >
    <strong
      class="notice-reason"
      data-test="group-approver-only-reason"
    >{{ $t(REASON_KEYS[action], { count: detail.count }) }}</strong>
    <p class="notice-body">
      {{ $t(action === 'delete' ? 'userGroups.approverOnly.howToDelete' : 'userGroups.approverOnly.howToSave') }}
      <template v-if="canRevert">
        {{ $t('userGroups.approverOnly.revertNote') }}
      </template>
    </p>
    <p
      v-if="detail.users.length"
      class="notice-names"
      data-test="group-approver-only-names"
    >
      <span>{{ $t('userGroups.approverOnly.affected') }}</span>
      <template
        v-for="(u, i) in detail.users"
        :key="u.id"
      >
        <span v-if="i > 0">、</span>
        <a
          v-if="linkable"
          :href="`/users/${u.id}?tab=roles`"
          target="_blank"
          rel="noopener"
          :title="$t('userGroups.approverOnly.linkTitle')"
          :data-test="`affected-user-${u.id}`"
        >{{ u.username }}</a>
        <span
          v-else
          :data-test="`affected-user-${u.id}`"
        >{{ u.username }}</span>
      </template>
      <span
        v-if="remaining > 0"
        data-test="group-approver-only-more"
      >{{ ' ' + $t('userGroups.approverOnly.more', { n: remaining }) }}</span>
    </p>
    <p
      v-if="linkable && detail.users.length"
      class="notice-hint"
    >
      {{ $t('userGroups.approverOnly.listNote') }}
    </p>
    <div class="notice-actions">
      <el-button
        type="primary"
        size="small"
        :loading="busy"
        data-test="group-approver-only-retry"
        @click="$emit('retry')"
      >
        {{ $t(action === 'delete' ? 'userGroups.approverOnly.retryDelete' : 'userGroups.approverOnly.retrySave') }}
      </el-button>
      <el-button
        v-if="canRevert"
        size="small"
        :disabled="busy"
        data-test="group-approver-only-revert"
        @click="$emit('revert')"
      >
        {{ $t('userGroups.approverOnly.revert') }}
      </el-button>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { canEnter, entryRuleFor } from '@/router/entryRules'

/**
 * 群組變更會讓成員只剩審核者角色時的就近說明：含人數的原因、處理方式、受影響成員帳號名
 * （能進使用者管理時為新分頁連結，原頁草稿保留）、「重新檢查」主要按鈕在前，
 * 群組角色把一般使用者由全系統收窄時其後另有「改回全系統」；按鈕組靠左，緊接說明文字。
 * 不替成員改直接指派；重送與還原由呼叫端執行。
 */
const props = defineProps({
  // { count, users: [{ id, username }] }
  detail: { type: Object, required: true },
  // save：群組角色；remove：成員移出；delete：刪除群組
  action: { type: String, default: 'save', validator: (v) => ['save', 'remove', 'delete'].includes(v) },
  canRevert: { type: Boolean, default: false },
  busy: { type: Boolean, default: false },
})
defineEmits(['retry', 'revert'])

const REASON_KEYS = {
  save: 'userGroups.approverOnly.reasonSave',
  remove: 'userGroups.approverOnly.reasonRemove',
  delete: 'userGroups.approverOnly.reasonDelete',
}
const linkable = computed(() => canEnter(entryRuleFor('/users')))
const remaining = computed(() => Math.max(0, props.detail.count - props.detail.users.length))
</script>

<style scoped>
.group-approver-only {
  margin-top: var(--ot-space-sm);
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--ot-warning);
  border-radius: var(--ot-radius-md);
  background: var(--ot-bg-hover);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
  text-align: left;
}
.notice-reason {
  display: block;
  color: var(--ot-text-primary);
}
.notice-body,
.notice-names,
.notice-hint {
  margin: var(--ot-space-xs) 0 0;
  line-height: 1.6;
  overflow-wrap: anywhere;
}
.notice-names a {
  color: var(--ot-primary);
}
.notice-actions {
  display: flex;
  justify-content: flex-start;
  gap: var(--ot-space-sm);
  margin-top: var(--ot-space-sm);
}
</style>
