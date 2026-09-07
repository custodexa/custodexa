<template>
  <div
    class="binding-list"
    data-test="binding-list"
  >
    <div class="list-head">
      <span class="section-title">
        {{ t('credentials.bindingsTitle', { count: bindings.length }) }}
      </span>
    </div>

    <p
      v-if="rotationActive && bindings.length"
      class="list-reason"
      data-test="bindings-blocked"
    >
      {{ t('credentials.blockedRotationActive') }}
    </p>

    <EmptyState
      v-if="!bindings.length"
      :title="t('credentials.bindingsEmptyTitle')"
      :hint="t('credentials.bindingsEmptyHint')"
      data-test="bindings-empty"
    />

    <div
      v-else
      class="rows"
    >
      <div
        v-for="binding in bindings"
        :key="binding.account_id"
        class="binding-row"
        :data-test="`binding-row-${binding.account_id}`"
      >
        <div class="row-main">
          <span class="asset-name">
            {{ binding.asset_name || t('common.assetRef', { id: binding.asset_id }) }}
          </span>
          <el-tag
            v-if="binding.is_default"
            size="small"
            type="info"
          >
            {{ t('credentials.bindingDefault') }}
          </el-tag>
          <el-tag
            v-if="binding.privileged"
            size="small"
            type="warning"
          >
            {{ t('credentials.bindingPrivileged') }}
          </el-tag>
          <span
            class="version"
            :data-test="`binding-version-${binding.account_id}`"
          >{{ versionText(binding) }}</span>
          <el-tag
            size="small"
            :type="binding.up_to_date ? 'success' : 'warning'"
            :data-test="`binding-state-${binding.account_id}`"
          >
            {{ binding.up_to_date
              ? t('credentials.bindingUpToDate')
              : t('credentials.bindingStale') }}
          </el-tag>
          <div class="row-actions">
            <el-button
              v-if="showDetach"
              link
              type="warning"
              :disabled="rotationActive"
              :data-test="`binding-detach-${binding.account_id}`"
              @click="emit('detach', binding)"
            >
              {{ t('credentials.detach') }}
            </el-button>
            <el-button
              link
              type="danger"
              :disabled="rotationActive"
              :data-test="`binding-unbind-${binding.account_id}`"
              @click="emit('unbind', binding)"
            >
              {{ t('credentials.unbind') }}
            </el-button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
/**
 * 憑證的掛載清單（設計稿 01 右側詳情下半）。
 *
 * 每列兩個動作，語義刻意分開：
 *   **脫離**會登入這台改密，主機上的密碼跟著變；
 *   **卸載**只移除掛載列，主機上的密碼原封不動。
 * 兩者長得很像而後果相反，故列上不做「動作可能不可用就灰掉」的靜默處理——
 * 不可執行時寫出原因，操作者才知道下一步該做什麼。原因寫在清單標頭下方一次：
 * 擋住每一列的是同一件事，逐列重複同一句話只是把清單變長。
 */
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import EmptyState from '@/components/EmptyState.vue'

const props = defineProps({
  bindings: { type: Array, default: () => [] },
  // scope 專用憑證沒有「脫離」可言：它本來就只屬於那一台
  scope: { type: String, default: 'shared' },
  rotationActive: { type: Boolean, default: false },
})

const emit = defineEmits(['detach', 'unbind'])

const { t } = useI18n()

// 專用憑證本來就只屬於那一台，沒有「脫離」可言：不是被擋住，是不存在這個動作
const showDetach = computed(() => props.scope === 'shared')

function versionText(binding) {
  if (!binding.effective_version_no) return t('credentials.bindingNoVersion')
  return t('credentials.versionNo', { no: binding.effective_version_no })
}
</script>

<style scoped>
.binding-list {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
  min-height: 0;
}

.list-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.section-title {
  font-size: var(--ot-font-size-sm);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.rows {
  display: flex;
  flex-direction: column;
  overflow-y: auto;
}

.binding-row {
  padding: var(--ot-space-xs) 0;
  border-bottom: 1px solid var(--ot-border-subtle);
}

.row-main {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  min-height: 32px;
  font-size: var(--ot-font-size-sm);
}

.asset-name {
  flex: 1;
  min-width: 0;
  font-weight: 500;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.version {
  font-family: var(--ot-font-mono);
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.row-actions {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  flex-shrink: 0;
}

.list-reason {
  margin: 0;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-disabled);
  line-height: 1.5;
}
</style>
