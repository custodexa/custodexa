<template>
  <!-- 分區卡片：依 key 分組渲染，後端新增政策鍵自動出現在對應區塊
       （四個設定域頁共用）。列的渲染在 PolicyKeyRow，第二層在 PolicyKeyDrawer -->
  <div
    v-for="section in sections"
    :key="section.title"
    class="policy-card"
  >
    <div class="card-header">
      <span class="card-title">{{ section.title }}</span>
      <span class="card-hint">{{ section.hint }}</span>
      <!-- 分區偏離數：同一鍵偏離多組只算一次；點它到合規對照頁看全系統視角。
           草稿判定在途或失敗時不印數字——那時手上只有已儲存值的舊判定，
           印出來等於拿舊答案冒充目前這一份編輯的結果 -->
      <span class="card-deviation">
        <span
          v-if="draftStatus === 'pending' || draftStatus === 'failed'"
          class="deviation-unknown"
          :data-test="`section-deviation-${section.id || section.title}`"
        >{{ draftStatus === 'pending'
          ? $t('policyKeySections.draftPending')
          : $t('policyKeySections.draftFailed') }}</span>
        <router-link
          v-else-if="deviationCount(section) > 0"
          class="deviation-link"
          :data-test="`section-deviation-${section.id || section.title}`"
          to="/compliance-map"
        >
          {{ $t('policyKeySections.deviation', { n: deviationCount(section) }, deviationCount(section)) }}
        </router-link>
        <span
          v-else
          class="deviation-ok"
          :data-test="`section-deviation-${section.id || section.title}`"
        >{{ $t('policyKeySections.noDeviation') }}</span>
        <el-tag
          v-if="draft"
          size="small"
          type="info"
          effect="plain"
        >
          {{ $t('policyKeySections.draftTag') }}
        </el-tag>
      </span>
    </div>

    <!-- 頁面專屬的區塊補充內容（跨欄位風險提示、專頁入口連結等） -->
    <slot
      name="section-extra"
      :section="section"
    />

    <PolicyKeyRow
      v-for="policy in section.policies"
      :key="policy.key"
      :policy="policy"
      :value="formValues[policy.key]"
      :deviating="deviatingKeys.has(policy.key)"
      @update:value="(key, value) => $emit('update:value', key, value)"
      @info="openDrawer(policy)"
    />

    <!-- 區塊尾端擴充（存取管控頁的資產覆寫表格等） -->
    <slot
      name="section-footer"
      :section="section"
    />
  </div>

  <PolicyKeyDrawer
    v-model="drawerVisible"
    :policy="activePolicy"
    :verdicts="activeVerdicts"
    :group-names="groupNames"
    :draft="draft"
  />
</template>

<script setup>
import { computed, ref } from 'vue'
import PolicyKeyRow from './PolicyKeyRow.vue'
import PolicyKeyDrawer from './PolicyKeyDrawer.vue'

const props = defineProps({
  // visibleSections 產物：[{ id, title, hint, policies: [policy] }]
  sections: { type: Array, required: true },
  // 編輯中值；寫入權在父層（update:value 事件）
  formValues: { type: Object, required: true },
  // 鍵→該鍵對各生效組的判定。判定一律由後端建構：前端自己算一份會與伺服器漂移，
  // 而分歧不會有任何一處報錯
  verdictsByKey: { type: Object, default: () => ({}) },
  // 政策組代號→顯示名
  groupNames: { type: Object, default: () => ({}) },
  // 判定是以尚未儲存的表單值算的
  draft: { type: Boolean, default: false },
  // 草稿判定的取得狀態：''／'ready'（有結果）、'pending'（在途）、'failed'（失敗）
  draftStatus: { type: String, default: '' },
})

defineEmits(['update:value'])

// 偏離鍵集：同一鍵對多組偏離只算一次（分區數字要是「幾個設定要處理」，
// 不是「幾筆判定不合格」）
const deviatingKeys = computed(() => {
  const keys = new Set()
  Object.entries(props.verdictsByKey).forEach(([key, verdicts]) => {
    if ((verdicts || []).some((v) => v.result === 'deviating')) keys.add(key)
  })
  return keys
})

const deviationCount = (section) =>
  section.policies.filter((p) => deviatingKeys.value.has(p.key)).length

const drawerVisible = ref(false)
const activePolicy = ref(null)

const activeVerdicts = computed(() =>
  activePolicy.value ? props.verdictsByKey[activePolicy.value.key] || [] : []
)

const openDrawer = (policy) => {
  activePolicy.value = policy
  drawerVisible.value = true
}
</script>

<style scoped>
.policy-card {
  padding: var(--ot-space-md);
  margin-bottom: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.card-header {
  display: flex;
  align-items: baseline;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-sm);
  padding-bottom: var(--ot-space-sm);
  border-bottom: 1px solid var(--ot-border-subtle);
}

.card-title {
  font-size: var(--ot-font-size-md);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.card-hint {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.card-deviation {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  margin-left: auto;
  font-size: var(--ot-font-size-sm);
}

.deviation-link {
  color: var(--el-color-warning);
  text-decoration: none;
}

.deviation-ok,
.deviation-unknown {
  color: var(--ot-text-secondary);
}

:deep(.policy-row + .policy-row) {
  border-top: 1px solid var(--ot-border-subtle);
}
</style>
