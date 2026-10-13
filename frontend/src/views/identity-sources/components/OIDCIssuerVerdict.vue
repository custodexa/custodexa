<template>
  <!-- 新增頁：儲存前不預覽判定（判定由伺服端現算，前端不自行推算） -->
  <div
    v-if="!isEdit"
    class="verdict verdict--pending"
    data-test="verdict-new-hint"
  >
    <el-icon class="verdict__icon">
      <Info />
    </el-icon>
    <span>{{ $t('identitySources.oidc.verdict.newHint') }}</span>
  </div>

  <div
    v-else-if="knownSource"
    class="verdict"
    data-test="issuer-verdict"
    :data-source="source"
  >
    <div class="verdict__head">
      <span class="verdict__label">{{ $t('identitySources.oidc.verdict.title') }}</span>
      <el-tag
        size="small"
        effect="plain"
        data-test="verdict-kind"
      >
        {{ $t(`oidcProviders.issuerKind.${kind === 'dedicated' ? 'dedicated' : 'shared'}`) }}
      </el-tag>
    </div>
    <p
      class="verdict__reason"
      data-test="verdict-reason"
    >
      {{ $t(`identitySources.oidc.verdict.plain.${source}`) }}
    </p>
    <p
      v-if="showEntraNote"
      class="verdict__note"
      data-test="verdict-entra-note"
    >
      <el-icon class="verdict__icon verdict__icon--info">
        <Info />
      </el-icon>
      <span>{{ $t('identitySources.oidc.verdict.entraNote') }}</span>
    </p>
    <button
      type="button"
      class="verdict__toggle"
      data-test="verdict-details-toggle"
      :aria-expanded="detailsOpen ? 'true' : 'false'"
      @click="detailsOpen = !detailsOpen"
    >
      {{ detailsOpen ? $t('identitySources.oidc.verdict.hideDetails') : $t('identitySources.oidc.verdict.showDetails') }}
      <el-icon>
        <ChevronDown v-if="detailsOpen" />
        <ChevronRight v-else />
      </el-icon>
    </button>
    <!-- 第二層：判定來源代碼、issuer 原文與部署設定名，給要排查的人看 -->
    <div
      v-if="detailsOpen"
      class="verdict__details"
      data-test="verdict-details"
    >
      <div>
        {{ $t('identitySources.oidc.verdict.detailSource', {
          label: $t(`identitySources.oidc.verdict.sourceLabel.${source}`),
          code: source,
        }) }}
      </div>
      <div>{{ $t('identitySources.oidc.verdict.detailIssuer', { issuer }) }}</div>
      <div>{{ $t(`identitySources.oidc.verdict.detail.${source}`) }}</div>
    </div>
  </div>
</template>

<script setup>
// 系統對 issuer 身分域的判定（多組織共用／本組織專屬）與原因，唯讀。
// 判定與來源取自伺服端回應的 issuer_kind／issuer_kind_source，與後端現算結果同源
import { computed, ref } from 'vue'
import { ChevronDown, ChevronRight, Info } from 'lucide-vue-next'

const SOURCES = ['builtin_list', 'admin_forced', 'deploy_declared', 'unknown_default']

const props = defineProps({
  isEdit: { type: Boolean, default: false },
  kind: { type: String, default: '' },
  source: { type: String, default: '' },
  issuer: { type: String, default: '' },
  // 提供者選擇器為 Entra
  entra: { type: Boolean, default: false },
})

const detailsOpen = ref(false)

const knownSource = computed(() => SOURCES.includes(props.source))

// Entra 來源判定為共用時常被誤讀成「不能登入」：補一句准入規則仍照常每次求值
const showEntraNote = computed(() => props.entra && props.source === 'unknown_default')
</script>

<style scoped>
.verdict {
  margin-bottom: var(--ot-space-md);
  padding: var(--ot-space-sm) var(--ot-space-md);
  background-color: var(--ot-bg-elevated);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md, 6px);
  color: var(--ot-text-primary);
  font-size: var(--ot-font-size-sm);
  line-height: 1.7;
}

.verdict--pending {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  color: var(--ot-text-secondary);
}

.verdict__head {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
}

.verdict__label {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

.verdict__reason {
  margin: var(--ot-space-xs) 0 0;
  font-weight: 600;
}

.verdict__note {
  display: flex;
  align-items: flex-start;
  gap: var(--ot-space-xs);
  margin: var(--ot-space-xs) 0 0;
}

.verdict__icon {
  flex-shrink: 0;
}

.verdict__note .verdict__icon {
  margin-top: 4px;
}

.verdict__icon--info {
  color: var(--ot-info);
}

.verdict__toggle {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  margin-top: var(--ot-space-xs);
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--ot-primary);
  font: inherit;
  font-size: var(--ot-font-size-xs);
  cursor: pointer;
}

.verdict__details {
  margin-top: var(--ot-space-xs);
  padding: var(--ot-space-sm);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-sm, 4px);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.7;
  overflow-wrap: anywhere;
}
</style>
