<template>
  <!-- 帳號名下方的小字：這一筆由哪個堡壘機專用帳號代改。提權方式放第二層，滑鼠滑過、鍵盤聚焦、觸控點按都能打開 -->
  <el-tooltip
    v-if="delegated"
    :visible="shown"
    manual
    placement="bottom-start"
    popper-class="execution-method-note-popper"
  >
    <template #content>
      <div data-test="execution-method-detail">
        <div v-if="!outOfScope">
          {{ detailText }}
        </div>
        <div>{{ elevationText }}</div>
        <div
          v-if="commandRejected"
          data-test="execution-method-sudo-help"
        >
          {{ t('changeSecretPlans.methodSudoHelp') }}
        </div>
      </div>
    </template>
    <span
      class="execution-method-note"
      tabindex="0"
      role="note"
      :aria-label="`${noteText}。${outOfScope ? '' : detailText}${elevationText}`"
      data-test="execution-method-note"
      @mouseenter="shown = true"
      @mouseleave="shown = false"
      @focus="shown = true"
      @blur="shown = false"
      @click="shown = !shown"
      @keydown.esc="shown = false"
    >
      <UserCog
        :size="12"
        aria-hidden="true"
      />
      <span class="execution-method-note__text">{{ noteText }}</span>
    </span>
  </el-tooltip>
</template>

<script setup>
// 改密紀錄的執行方式標示：取紀錄本身的 execution_method 與 executor_username（執行當下的快照），
// 不看資產現況。自改、舊資料與帳號名為空的列不渲染。
// 專用帳號不在檢視者的憑證範圍內時（executor_out_of_scope）後端不給帳號名，畫面只顯示類別句，不帶名稱。
import { computed, ref } from 'vue'
import { UserCog } from 'lucide-vue-next'
import { useI18n } from 'vue-i18n'

const props = defineProps({
  row: { type: Object, default: () => ({}) },
})

const { t, te } = useI18n()
const shown = ref(false)

const DELEGATED = ['executor_root', 'executor_sudo_nopasswd', 'executor_sudo_password']

// 改密指令被拒時，第二層才提 sudo 規則並指向營運文件的設定一節（第一層的原因文案不提 sudo）
const commandRejected = computed(() => props.row?.error === 'CHANGE_SECRET_EXECUTOR_COMMAND_REJECTED')
const outOfScope = computed(() => props.row?.executor_out_of_scope === true)
const delegated = computed(
  () =>
    DELEGATED.includes(props.row?.execution_method) &&
    (outOfScope.value || !!props.row?.executor_username),
)
const noteText = computed(() =>
  outOfScope.value
    ? t('changeSecretPlans.methodDelegatedByScoped')
    : t('changeSecretPlans.methodDelegatedBy', { name: props.row.executor_username }),
)
const methodLabel = computed(() => {
  const key = `changeSecretPlans.method.${props.row.execution_method}`
  return te(key) ? t(key) : props.row.execution_method
})
const detailText = computed(() =>
  t('changeSecretPlans.methodDetail', {
    executor: props.row.executor_username,
    account: props.row.account_username || '',
    method: methodLabel.value,
  }),
)
const elevationText = computed(() => t('changeSecretPlans.methodElevation', { method: methodLabel.value }))
</script>

<style scoped>
.execution-method-note {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  max-width: 100%;
  font-size: 12px;
  line-height: 18px;
  color: var(--ot-text-secondary);
  cursor: default;
}

.execution-method-note :deep(svg) {
  flex: none;
}

.execution-method-note__text {
  min-width: 0;
  overflow-wrap: anywhere;
}

.execution-method-note:focus-visible {
  outline: 2px solid var(--ot-primary);
  outline-offset: 1px;
}
</style>

<style>
/* tooltip 掛在 body 下，scoped 樣式管不到，另以 popper-class 限寬 */
.execution-method-note-popper.el-popper {
  max-width: 320px;
  white-space: normal;
  line-height: 1.6;
}
</style>
