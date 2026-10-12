<template>
  <div class="mapping-entry">
    <slot name="attr" />

    <!-- 來源尚未建立：規則以來源為軸，沒有來源就沒有可進入的映射頁 -->
    <el-alert
      v-if="!sourceId"
      class="mapping-entry__notice"
      type="info"
      :title="$t('identitySources.mapping.needSaveFirst')"
      :closable="false"
      show-icon
    />
    <!-- 只放摘要與入口：規則的檢視與編輯只在外部群組映射頁一處，
         詳情頁不列規則，避免同一份規則有兩個編輯處 -->
    <div
      v-else
      class="mapping-entry__bar"
    >
      <span
        class="mapping-entry__summary"
        :aria-busy="state === 'loading' ? 'true' : 'false'"
        data-test="mapping-summary"
      >{{ summaryText }}</span>
      <router-link
        :to="manageLink"
        class="mapping-entry__link"
        data-test="mapping-manage-link"
      >
        <el-button type="primary">
          {{ $t('identitySources.mapping.manage') }}
        </el-button>
      </router-link>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch, onMounted } from 'vue'
import { t } from '@/i18n'
import { getIdentitySources } from '@/api/identitySources'

const props = defineProps({
  type: { type: String, required: true },
  // 來源尚未儲存時為 null：此時只顯示提示，不呼叫任何端點
  sourceId: { type: [Number, String], default: null },
})

// loading | unavailable | ready
const state = ref('loading')
const counts = ref({ roles: 0, userGroups: 0 })

const manageLink = computed(() =>
  `/identity-sources/${encodeURIComponent(props.type)}/${encodeURIComponent(props.sourceId)}/group-mappings`
)

const isCount = (v) => typeof v === 'number' && Number.isFinite(v)

// 數字取自來源列表同一支 API 的同兩個欄位，使列表、詳情頁摘要與映射頁三處一致。
// 讀不到（請求失敗、找不到本列、欄位非數字）一律明示讀不到，不可顯示成 0——
// 0 是「沒有規則」的答案，拿它頂替失敗會誤導管理者
const load = async () => {
  if (!props.sourceId) return
  state.value = 'loading'
  try {
    const res = await getIdentitySources()
    const rows = Array.isArray(res?.data) ? res.data : []
    const row = rows.find((r) => r?.type === props.type && String(r?.id) === String(props.sourceId))
    const roles = row?.role_mapping_rule_count
    const userGroups = row?.user_group_mapping_rule_count
    if (!isCount(roles) || !isCount(userGroups)) {
      state.value = 'unavailable'
      return
    }
    counts.value = { roles, userGroups }
    state.value = 'ready'
  } catch {
    state.value = 'unavailable'
  }
}

const summaryText = computed(() => {
  if (state.value === 'loading') return ''
  if (state.value === 'unavailable') return t('identitySources.mapping.summaryUnavailable')
  const { roles, userGroups } = counts.value
  if (roles === 0 && userGroups === 0) return t('identitySources.mapping.summaryNone')
  return t('identitySources.mapping.summary', { roles, userGroups })
})

watch(() => props.sourceId, load)
onMounted(load)
</script>

<style scoped>
.mapping-entry__notice {
  margin-top: var(--ot-space-sm);
}

.mapping-entry__bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--ot-space-md);
  margin-top: var(--ot-space-sm);
  padding: var(--ot-space-sm) var(--ot-space-md);
  background: var(--ot-bg-elevated);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}

.mapping-entry__summary {
  min-height: 20px;
  color: var(--ot-text-primary);
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
}

.mapping-entry__link {
  flex-shrink: 0;
}
</style>
