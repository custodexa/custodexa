<template>
  <div
    v-if="done"
    class="approver-only-banner is-done"
    role="status"
    data-test="approver-only-done"
  >
    {{ $t('users.approverOnlyBanner.done') }}
  </div>
  <div
    v-else
    class="approver-only-banner"
    data-test="approver-only-banner"
  >
    <div class="banner-text">
      {{ $t('users.approverOnlyBanner.body') }}
      <div
        v-if="dirty"
        class="banner-dirty"
        data-test="approver-only-banner-dirty"
      >
        {{ $t('users.approverOnlyBanner.dirtyNote') }}
      </div>
    </div>
    <el-button
      type="primary"
      size="small"
      :disabled="dirty"
      :loading="busy"
      data-test="approver-only-add-user"
      @click="$emit('add')"
    >
      {{ $t('users.approverOnlyBanner.addButton') }}
    </el-button>
  </div>
</template>

<script setup>
/**
 * 角色與範圍分頁頂端的說明條：帳號只有審核者角色時顯示，按鈕以目前已儲存的指派加上
 * 全系統的一般使用者整組儲存（只加不減，不另跳確認）。下方有未儲存的修改時按鈕停用，
 * 避免兩份角色清單互相覆蓋。成功後原地換成完成句。
 */
defineProps({
  dirty: { type: Boolean, default: false },
  busy: { type: Boolean, default: false },
  done: { type: Boolean, default: false },
})
defineEmits(['add'])
</script>

<style scoped>
.approver-only-banner {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: var(--ot-space-md);
  margin-bottom: var(--ot-space-md);
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--ot-warning);
  border-radius: var(--ot-radius-md);
  background: var(--ot-bg-hover);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-primary);
}
.approver-only-banner.is-done {
  border-color: var(--ot-success);
}
.banner-dirty {
  margin-top: var(--ot-space-xs);
  color: var(--ot-text-secondary);
}
@media (max-width: 900px) {
  .approver-only-banner {
    flex-direction: column;
  }
}
</style>
