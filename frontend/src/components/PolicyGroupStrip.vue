<template>
  <!-- 頁首列：現在對照的是哪幾組、去哪裡管它們、以及本頁的套用與儲存。
       全系統的偏離視角在合規對照頁，不在這裡——設定頁只講本頁的事。
       用 output 而非帶 role 的 div：對輔助技術是同一件事（隱含 status），
       但語義寫在標籤上，後續改版不會順手把它拿掉 -->
  <output
    v-loading="loading"
    class="policy-strip"
  >
    <div class="strip-groups">
      <span class="strip-label">{{ $t('policyStrip.groupsLabel') }}</span>
      <el-tag
        v-for="group in groups"
        :key="group.code"
        size="small"
        effect="plain"
        :data-test="`strip-group-${group.code}`"
      >
        {{ group.name || group.code }}
      </el-tag>
      <span
        v-if="groups.length === 0"
        class="strip-empty"
      >{{ $t('policyStrip.noGroups') }}</span>
      <router-link
        class="strip-link"
        to="/policy-groups"
      >
        {{ $t('policyStrip.manage') }}
      </router-link>
      <router-link
        class="strip-link"
        to="/compliance-map"
      >
        {{ $t('policyStrip.map') }}
      </router-link>
      <el-tag
        v-if="isDirty"
        type="info"
        size="small"
        effect="plain"
      >
        {{ $t('policyStrip.unsaved') }}
      </el-tag>
    </div>

    <!-- 頁面專屬的補充內容 -->
    <slot name="extra" />

    <div class="strip-actions">
      <el-dropdown
        :disabled="loading || saving"
        @command="$emit('apply', $event)"
      >
        <el-button :disabled="loading || saving">
          {{ $t('policyStrip.apply') }}
        </el-button>
        <template #dropdown>
          <el-dropdown-menu>
            <el-dropdown-item
              v-for="group in groups"
              :key="group.code"
              :command="{ mode: 'group', groupCode: group.code }"
            >
              {{ $t('policyStrip.applyGroup', { group: group.name || group.code }) }}
            </el-dropdown-item>
            <el-dropdown-item
              divided
              :command="{ mode: 'strictest' }"
            >
              {{ $t('policyStrip.applyStrictest') }}
            </el-dropdown-item>
          </el-dropdown-menu>
        </template>
      </el-dropdown>
      <el-button
        :disabled="!isDirty || saving"
        @click="$emit('reset')"
      >
        {{ $t('policyStrip.revert') }}
      </el-button>
      <el-button
        type="primary"
        :disabled="!isDirty"
        :loading="saving"
        @click="$emit('save')"
      >
        {{ $t('common.save') }}
      </el-button>
    </div>
  </output>
</template>

<script setup>
defineProps({
  loading: { type: Boolean, default: false },
  saving: { type: Boolean, default: false },
  isDirty: { type: Boolean, default: false },
  // 生效政策組（政策列表 API 的頂層 groups）
  groups: { type: Array, default: () => [] },
})

defineEmits(['apply', 'reset', 'save'])
</script>

<style scoped>
.policy-strip {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--ot-space-md);
  flex-wrap: wrap;
  padding: var(--ot-space-md);
  margin-bottom: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.strip-groups {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  flex-wrap: wrap;
  color: var(--ot-text-primary);
}

.strip-label,
.strip-empty {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.strip-link {
  font-size: var(--ot-font-size-sm);
  color: var(--el-color-primary);
  text-decoration: none;
}

.strip-actions {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
}
</style>
