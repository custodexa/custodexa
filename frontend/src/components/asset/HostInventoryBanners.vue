<template>
  <!-- 警示帶：部分完成或失敗、中斷 -->
  <section
    v-if="scan && scan.status === 'partial'"
    class="inv-banner is-warning"
    data-test="inv-banner-partial"
  >
    <strong>{{ $t('hostInventory.partial.title') }}</strong>
    <ul>
      <li
        v-for="g in gaps"
        :key="g.check"
      >
        {{ gapText(g) }}
      </li>
    </ul>
    <p>{{ $t('hostInventory.partial.after') }}</p>
    <details
      class="inv-banner-hint"
      data-test="inv-partial-hint"
    >
      <summary>{{ $t('hostInventory.partial.hintTitle') }}</summary>
      <p data-test="inv-partial-hint-text">
        {{ partialHint }}
      </p>
      <el-button
        v-if="canManageExecutor"
        size="small"
        type="primary"
        data-test="inv-partial-go-executor"
        @click="emit('goto', 'executor-test-login')"
      >
        {{ $t('hostInventory.partial.hintGo') }}
      </el-button>
    </details>
  </section>
  <section
    v-if="scan && scan.status === 'failed'"
    class="inv-banner is-danger"
    data-test="inv-banner-failed"
  >
    <p>{{ failure.known ? $t(`hostInventory.failure.${failure.code}`) : $t('hostInventory.failure.generic') }}</p>
    <p
      v-if="failure.known && failureMore"
      class="inv-banner-hint"
    >
      {{ failureMore }}
    </p>
    <p
      v-if="!failure.known && failure.code"
      class="inv-banner-code"
      data-test="inv-failure-code"
    >
      {{ $t('hostInventory.failure.code', { code: failure.code }) }}
    </p>
    <el-button
      v-if="failure.next === 'goHostKey' && canEditAsset"
      size="small"
      data-test="inv-go-hostkey"
      @click="emit('goto', 'hostkey')"
    >
      {{ $t('hostInventory.goHostKey') }}
    </el-button>
    <el-button
      v-else-if="failure.next === 'goAccounts' && canEditAsset"
      size="small"
      data-test="inv-go-accounts-failed"
      @click="emit('goto', 'accounts')"
    >
      {{ $t('hostInventory.goAccounts') }}
    </el-button>
    <el-button
      v-else-if="failure.next === 'goExecutor' && canManageExecutor"
      size="small"
      data-test="inv-go-executor-failed"
      @click="emit('goto', 'executor-test-login')"
    >
      {{ $t('hostInventory.goExecutor') }}
    </el-button>
  </section>
  <section
    v-if="scan && scan.status === 'interrupted'"
    class="inv-banner is-info"
    data-test="inv-banner-interrupted"
  >
    <p>{{ $t('hostInventory.line.interrupted') }}</p>
  </section>
</template>

<script setup>
import { computed } from 'vue'
import { t, te } from '@/i18n'
import { failureInfo, isCoverageGap } from '@/utils/hostInventoryPresentation'
import { gapText } from '@/utils/hostInventoryLabels'
import { visibleText } from '@/utils/visibleName'

// 盤點抽屜的警示帶：部分完成列出缺項與後果、失敗給白話原因與下一步、中斷說明先前結果不變
const props = defineProps({
  scan: { type: Object, default: null },
  coverage: { type: Array, default: () => [] },
  canEditAsset: { type: Boolean, default: false },
  canManageExecutor: { type: Boolean, default: false },
  // 專用帳號名：只有持專用帳號管理權者拿得到，空字串時用代稱
  executorName: { type: String, default: '' },
})
const emit = defineEmits(['goto'])

const gaps = computed(() => props.coverage.filter(isCoverageGap))
const failure = computed(() => failureInfo(props.scan?.failure_reason))
// 補齊說明依這次盤點用的身分：已是專用帳號就說「讓它能讀取」，否則建議設定專用帳號
const partialHint = computed(() => {
  if (props.scan?.identity_mode !== 'executor') return t('hostInventory.partial.hint')
  return props.executorName
    ? t('hostInventory.partial.hintExecutor', { account: visibleText(props.executorName) })
    : t('hostInventory.partial.hintExecutorNoName')
})
const failureMore = computed(() => {
  const key = `hostInventory.failure.${failure.value.code}_more`
  return te(key) ? t(key) : ''
})
</script>

<style scoped>
.inv-banner {
  padding: 12px 16px;
  margin-bottom: 12px;
  border-radius: var(--ot-radius-md);
  border: 1px solid var(--ot-border);
  font-size: 13px;
  line-height: 1.7;
}

.inv-banner p,
.inv-banner ul {
  margin: 4px 0;
}

.inv-banner.is-warning {
  border-color: var(--ot-warning);
}

.inv-banner.is-danger {
  border-color: var(--ot-danger);
}

.inv-banner-hint,
.inv-banner-code {
  color: var(--ot-text-secondary);
}

.inv-banner-code {
  font-family: var(--ot-font-mono);
}
</style>
