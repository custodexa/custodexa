<template>
  <!-- 主機身分變更後的人工確認。這是唯一的確認入口：先說明「新憑證有沒有送出去」，
       再給「現在記錄的金鑰與送出時是否相同」的結論，細節（指紋等）收在詳細資訊。
       指紋不同時多一道明確同意。API 不回秘密、公鑰本體與來源資產，這裡也不顯示。 -->
  <el-dialog
    :model-value="modelValue"
    :title="$t('hostIdentityConfirm.title')"
    width="min(560px, calc(100vw - 32px))"
    data-test="host-identity-dialog"
    @update:model-value="$emit('update:modelValue', $event)"
  >
    <div
      v-if="identity"
      class="hic-body"
    >
      <div
        class="hic-target"
        data-test="hic-target"
      >
        {{ $t('hostIdentityConfirm.target', { asset: asset, account: account }) }}
      </div>

      <div
        v-if="expired && !isBlocked"
        class="hic-callout hic-callout-warning"
        data-test="hic-expired-notice"
      >
        <TriangleAlert
          class="hic-callout-icon"
          :size="16"
          aria-hidden="true"
        />
        <div class="hic-callout-text">
          {{ $t('hostIdentityConfirm.expiredNotice', { time: deadlineText }) }}
        </div>
      </div>

      <div
        v-if="isDifferentKey"
        class="hic-callout hic-callout-danger"
        data-test="hic-different-key"
      >
        <CircleX
          class="hic-callout-icon"
          :size="16"
          aria-hidden="true"
        />
        <div class="hic-callout-text">
          <div class="hic-callout-title hic-danger">
            {{ $t('hostIdentityConfirm.differentKey.title') }}
          </div>
          <div>{{ $t('hostIdentityConfirm.differentKey.body') }}</div>
        </div>
      </div>

      <p
        v-if="isBlocked && blockedKind === 'resetPending'"
        class="hic-intro"
        data-test="hic-intro"
      >
        {{ $t(introKey) }}
      </p>

      <template v-if="isBlocked">
        <p
          class="hic-intro"
          data-test="hic-blocked-body"
        >
          {{ blockedBody }}
        </p>
      </template>

      <div
        v-else-if="isLegacy"
        class="hic-callout hic-callout-warning"
        data-test="hic-legacy-intro"
      >
        <TriangleAlert
          class="hic-callout-icon hic-warning"
          :size="16"
          aria-hidden="true"
        />
        <div class="hic-callout-text">
          {{ $t(isWinrm ? 'hostIdentityConfirm.legacy.introWinrm' : 'hostIdentityConfirm.legacy.intro') }}
        </div>
      </div>

      <p
        v-else
        class="hic-intro"
        data-test="hic-intro"
      >
        {{ $t(introKey) }}
      </p>

      <div class="hic-summary">
        <template v-if="blockedKind === 'transportChanged'">
          <div class="hic-row">
            <span class="hic-label">{{ $t('hostIdentityConfirm.summary.channelOriginalLabel') }}</span>
            <span
              class="hic-value"
              data-test="hic-channel-original"
            >{{ transportLabel(original?.transport) }}</span>
          </div>
          <div class="hic-row hic-row-border">
            <span class="hic-label">{{ $t('hostIdentityConfirm.summary.channelCurrentLabel') }}</span>
            <span
              class="hic-value"
              data-test="hic-channel-current"
            >{{ transportLabel(current.transport) }}</span>
            <span class="hic-tag hic-tag-danger">{{ $t('hostIdentityConfirm.summary.relationDifferent') }}</span>
          </div>
        </template>
        <div
          v-else-if="blockedKind === 'resetPending'"
          class="hic-row"
        >
          <span class="hic-label">{{ $t('hostIdentityConfirm.summary.keyLabel') }}</span>
          <span
            class="hic-value"
            data-test="hic-current-reset"
          >{{ $t('hostIdentityConfirm.summary.currentReset') }}</span>
        </div>
        <template v-else-if="isWinrm">
          <div class="hic-row">
            <span class="hic-label">{{ $t('hostIdentityConfirm.summary.channelLabel') }}</span>
            <span
              class="hic-value"
              data-test="hic-channel-winrm"
            >{{ transportLabel('winrm') }}</span>
          </div>
          <div class="hic-row hic-row-border">
            <span class="hic-label">{{ $t('hostIdentityConfirm.summary.keyLabel') }}</span>
            <span class="hic-value">
              <strong>{{ $t('hostIdentityConfirm.summary.relationUnavailable') }}</strong>
              <span
                class="hic-tag hic-tag-muted"
                data-test="hic-winrm-no-key"
              >{{ $t('hostIdentityConfirm.summary.winrmNoKey') }}</span>
            </span>
          </div>
        </template>
        <div
          v-else-if="!blockedKind"
          class="hic-row"
        >
          <span class="hic-label">{{ $t('hostIdentityConfirm.summary.keyLabel') }}</span>
          <span class="hic-value">
            <template v-if="isLegacy">
              <strong data-test="hic-relation">{{ $t('hostIdentityConfirm.summary.relationUnavailable') }}</strong>
              <span
                class="hic-tag hic-tag-muted"
                data-test="hic-relation-hint"
              >{{ $t('hostIdentityConfirm.summary.relationUnavailableHint') }}</span>
            </template>
            <template v-else>
              {{ $t('hostIdentityConfirm.summary.relationLabel') }}
              <span
                :class="['hic-tag', isDifferentKey ? 'hic-tag-danger' : 'hic-tag-success']"
                data-test="hic-relation"
              >{{ $t(isDifferentKey
                ? 'hostIdentityConfirm.summary.relationDifferent'
                : 'hostIdentityConfirm.summary.relationSame') }}</span>
            </template>
          </span>
        </div>
        <div
          class="hic-row"
          :class="{ 'hic-row-border': hasRowAbove }"
        >
          <span class="hic-label">{{ $t('hostIdentityConfirm.summary.deadlineLabel') }}</span>
          <span
            class="hic-value"
            data-test="hic-deadline"
          >{{ deadlineLine }}</span>
        </div>
      </div>

      <div
        v-if="isBlocked"
        class="hic-callout hic-callout-warning"
        data-test="hic-blocked"
      >
        <TriangleAlert
          class="hic-callout-icon hic-warning"
          :size="16"
          aria-hidden="true"
        />
        <div class="hic-callout-text">
          <div
            data-test="hic-blocked-action"
          >
            {{ blockedAction }}
          </div>
          <div
            v-if="blockedKind === 'transportChanged'"
            class="hic-blocked-action"
            data-test="hic-blocked-new-work"
          >
            {{ $t(isMemberKind ? 'hostIdentityConfirm.blocked.newWorkMember' : 'hostIdentityConfirm.blocked.newWorkCandidate') }}
          </div>
        </div>
      </div>

      <p
        v-if="!isBlocked"
        class="hic-hint"
      >
        {{ $t(isWinrm ? 'hostIdentityConfirm.checkHintWinrm' : 'hostIdentityConfirm.checkHint') }}
      </p>

      <div
        v-if="isBlocked || !isWinrm"
        class="hic-details"
      >
        <button
          type="button"
          class="hic-link"
          :aria-expanded="detailsOpen"
          data-test="hic-details-toggle"
          @click="detailsOpen = !detailsOpen"
        >
          {{ $t(detailsOpen ? 'hostIdentityConfirm.details.hide' : 'hostIdentityConfirm.details.show') }}
        </button>
        <div
          v-if="detailsOpen"
          class="hic-grid"
          data-test="hic-details"
        >
          <div class="hic-grid-row hic-grid-head">
            <span />
            <span>{{ $t('hostIdentityConfirm.details.original') }}</span>
            <span>{{ $t('hostIdentityConfirm.details.current') }}</span>
          </div>
          <div class="hic-grid-row">
            <span class="hic-label">{{ $t('hostIdentityConfirm.details.fingerprint') }}</span>
            <span
              v-if="original"
              class="hic-mono"
            >{{ original.fingerprint }}</span>
            <span
              v-else
              class="hic-muted"
              data-test="hic-legacy-original"
            >{{ $t('hostIdentityConfirm.details.legacyOriginal') }}</span>
            <span :class="['hic-mono', { 'hic-danger': isDifferentKey }]">
              {{ current.fingerprint || '—' }}
              <button
                v-if="current.fingerprint"
                type="button"
                class="hic-link hic-link-sm"
                data-test="hic-copy"
                @click="copyFingerprint"
              >{{ $t('hostIdentityConfirm.details.copy') }}</button>
            </span>
          </div>
          <div class="hic-grid-row">
            <span class="hic-label">{{ $t('hostIdentityConfirm.details.algorithm') }}</span>
            <span>{{ original ? original.algorithm : '—' }}</span>
            <span>{{ current.algorithm || '—' }}</span>
          </div>
          <div class="hic-grid-row">
            <span class="hic-label">{{ $t('hostIdentityConfirm.details.record') }}</span>
            <span>{{ recordText(original) }}</span>
            <span :class="{ 'hic-danger': generationChanged }">{{ recordText(current) }}</span>
          </div>
          <div class="hic-grid-row">
            <span class="hic-label">{{ $t('hostIdentityConfirm.details.time') }}</span>
            <span data-test="hic-sent-at">{{ original ? $t('hostIdentityConfirm.details.sentAt', { time: fmt(original.bound_at) }) : '—' }}</span>
            <span data-test="hic-recorded-at">{{ current.recorded_at ? $t('hostIdentityConfirm.details.updatedAt', { time: fmt(current.recorded_at) }) : '—' }}</span>
          </div>
        </div>
      </div>

      <template v-if="!isBlocked">
        <div
          class="hic-callout hic-callout-info"
          data-test="hic-foot"
        >
          <Info
            class="hic-callout-icon hic-info"
            :size="16"
            aria-hidden="true"
          />
          <div class="hic-callout-text">
            {{ footText }}
          </div>
        </div>

        <el-checkbox
          v-model="identityChecked"
          class="hic-check"
          data-test="hic-check-identity"
        >
          {{ $t('hostIdentityConfirm.confirm.identity') }}
        </el-checkbox>
        <el-checkbox
          v-if="isDifferentKey"
          v-model="differentKeyChecked"
          class="hic-check"
          data-test="hic-check-different-key"
        >
          {{ $t('hostIdentityConfirm.confirm.differentKey') }}
        </el-checkbox>
      </template>
    </div>

    <template #footer>
      <el-button
        v-if="isBlocked"
        data-test="hic-close"
        @click="$emit('update:modelValue', false)"
      >
        {{ $t('hostIdentityConfirm.button.close') }}
      </el-button>
      <el-button
        v-if="!isBlocked"
        data-test="hic-cancel"
        @click="$emit('update:modelValue', false)"
      >
        {{ $t('hostIdentityConfirm.button.cancel') }}
      </el-button>
      <el-button
        v-if="!isBlocked"
        type="primary"
        :disabled="!canSubmit"
        :loading="submitting"
        data-test="hic-submit"
        @click="submit"
      >
        {{ $t('hostIdentityConfirm.button.submit') }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { TriangleAlert, CircleX, Info } from 'lucide-vue-next'
import { formatDateTime } from '@/utils/format'

// identity 即後端回的 host_identity 物件。可確認時給確認流程；confirmable 為 false 時只說明
// 為什麼不能在這裡確認、只有「關閉」；original 為 null 是升級前的舊工作，只能人工確認一次。
const props = defineProps({
  modelValue: { type: Boolean, default: false },
  asset: { type: String, default: '' },
  account: { type: String, default: '' },
  identity: { type: Object, default: null },
  // 候選或輪替成員：不可確認時「改以新工作」的指引兩者不同
  kind: { type: String, default: 'candidate' },
  submitting: { type: Boolean, default: false },
})
const emit = defineEmits(['update:modelValue', 'confirm'])

const { t } = useI18n()

const original = computed(() => props.identity?.original ?? null)
const current = computed(() => props.identity?.current ?? {})
const isWinrm = computed(() => current.value.transport === 'winrm')
const expired = computed(() => props.identity?.expired === true)
const isBlocked = computed(() => props.identity?.confirmable === false)

// 同鑰／不同鑰只看指紋；WinRM 沒有金鑰可比，不會落到不同鑰
const isDifferentKey = computed(
  () =>
    !isBlocked.value &&
    !isWinrm.value &&
    !!original.value &&
    original.value.fingerprint !== current.value.fingerprint
)
const generationChanged = computed(
  () => !!original.value && original.value.generation !== current.value.generation
)

const isMemberKind = computed(() => props.kind === 'member')
const isLegacy = computed(() => !isBlocked.value && !!props.identity && original.value === null)

// 不可確認的三種原因；沒對上的狀態當作「沒有可核對的記錄」
const blockedKind = computed(() => {
  if (!isBlocked.value) return ''
  const status = props.identity?.status
  if (status === 'reset_pending') return 'resetPending'
  if (status === 'transport_changed') return 'transportChanged'
  return 'recordMissing'
})
const transportLabel = (value) => (value === 'winrm' ? 'WinRM' : value === 'ssh' ? 'SSH' : '—')
const blockedBody = computed(() => {
  if (blockedKind.value === 'transportChanged') {
    return t('hostIdentityConfirm.blocked.transportChanged', {
      from: transportLabel(original.value?.transport),
      to: transportLabel(current.value.transport),
    })
  }
  return t(`hostIdentityConfirm.blocked.${blockedKind.value}`)
})
const blockedAction = computed(() => {
  if (blockedKind.value === 'transportChanged') {
    return t('hostIdentityConfirm.blocked.transportRestore', {
      from: transportLabel(original.value?.transport),
    })
  }
  return t('hostIdentityConfirm.blocked.contactAdmin')
})
// 摘要表第二列（期限）上方是否還有一列
const hasRowAbove = computed(() => blockedKind.value !== 'recordMissing')

// 第一層依「這次是否已用新憑證登入」選句，不看 phase
const introKey = computed(() => {
  const sent = props.identity?.verification_sent
  if (sent === true) return 'hostIdentityConfirm.intro.verifiedNotApplied'
  if (sent === 'unknown') return 'hostIdentityConfirm.intro.unknown'
  return 'hostIdentityConfirm.intro.notSent'
})

const fmt = (value) => formatDateTime(value)
const deadlineText = computed(() => fmt(props.identity?.deadline))
const deadlineLine = computed(() =>
  t(
    expired.value
      ? 'hostIdentityConfirm.summary.deadlineExpired'
      : 'hostIdentityConfirm.summary.deadlineActive',
    { time: deadlineText.value }
  )
)

// 逾期後期限不會重算，說明句不能再說「期限也不變」
const footText = computed(() => {
  const deadline = deadlineText.value
  if (isWinrm.value) return t('hostIdentityConfirm.foot.winrm')
  if (expired.value || isLegacy.value) return t('hostIdentityConfirm.foot.expired')
  if (isDifferentKey.value) return t('hostIdentityConfirm.foot.differentKey', { deadline })
  return t('hostIdentityConfirm.foot.default', { deadline })
})

const recordText = (side) =>
  side && side.generation != null
    ? t('hostIdentityConfirm.details.recordValue', { id: side.record_id, generation: side.generation })
    : '—'

const detailsOpen = ref(false)
const identityChecked = ref(false)
const differentKeyChecked = ref(false)

// 每次開啟或換一筆身分都重置：勾選不得沿用上一筆的同意
watch(
  () => [props.modelValue, props.identity],
  () => {
    identityChecked.value = false
    differentKeyChecked.value = false
    detailsOpen.value = isDifferentKey.value
  },
  { immediate: true }
)

const canSubmit = computed(
  () =>
    !!props.identity &&
    !isBlocked.value &&
    !props.submitting &&
    identityChecked.value &&
    (!isDifferentKey.value || differentKeyChecked.value)
)

function submit() {
  if (!canSubmit.value) return
  const cur = current.value
  const payload = { transport: cur.transport }
  if (!isWinrm.value) {
    payload.record_id = cur.record_id
    payload.algorithm = cur.algorithm
    payload.fingerprint = cur.fingerprint
    payload.generation = cur.generation
  }
  payload.accept_different_key = isDifferentKey.value
  emit('confirm', payload)
}

async function copyFingerprint() {
  try {
    await navigator.clipboard.writeText(current.value.fingerprint)
  } catch {
    // 剪貼簿不可用時指紋仍可手動選取
  }
}
</script>

<style scoped>
.hic-body {
  min-width: 0;
  /* 內容過長時只捲內文，底部按鈕永遠留在視窗內 */
  max-height: calc(100vh - 220px);
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 12px;
  color: var(--ot-text-primary);
}
.hic-target {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}
.hic-intro {
  margin: 0;
  font-size: var(--ot-font-size-md);
  line-height: 1.6;
}
.hic-hint {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
  color: var(--ot-text-secondary);
}
.hic-summary {
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  background: var(--ot-bg-page);
  font-size: var(--ot-font-size-sm);
}
.hic-row {
  display: flex;
  gap: 12px;
  padding: 8px 12px;
}
.hic-row-border {
  border-top: 1px solid var(--ot-border-subtle);
}
.hic-label {
  flex: none;
  width: 112px;
  color: var(--ot-text-secondary);
}
.hic-value {
  flex: 1;
  min-width: 0;
}
.hic-tag {
  margin-left: 6px;
  display: inline-flex;
  align-items: center;
  height: 20px;
  padding: 0 7px;
  border-radius: var(--ot-radius-sm);
  font-size: var(--ot-font-size-xs);
}
.hic-tag-success {
  color: var(--ot-success);
  border: 1px solid var(--ot-success);
}
.hic-tag-danger {
  color: var(--ot-danger);
  border: 1px solid var(--ot-danger);
}
.hic-tag-muted {
  color: var(--ot-text-secondary);
  border: 1px solid var(--ot-border);
}
.hic-muted {
  color: var(--ot-text-secondary);
}
.hic-blocked-action {
  margin-top: 8px;
}
.hic-danger {
  color: var(--ot-danger);
}
.hic-callout {
  display: flex;
  gap: 10px;
  padding: 10px 12px;
  border-radius: var(--ot-radius-md);
  border: 1px solid var(--ot-border);
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
}
.hic-callout-icon {
  flex: none;
  margin-top: 3px;
}
.hic-callout-text {
  flex: 1;
  min-width: 0;
}
.hic-warning {
  color: var(--ot-warning);
}
.hic-info {
  color: var(--ot-primary);
}
.hic-strong,
strong {
  font-weight: 600;
}
.hic-callout-title {
  font-weight: 600;
  margin-bottom: 4px;
}
.hic-callout-danger {
  border-color: var(--ot-danger);
  background: color-mix(in srgb, var(--ot-danger) 10%, transparent);
}
.hic-callout-warning {
  border-color: var(--ot-warning);
  background: color-mix(in srgb, var(--ot-warning) 10%, transparent);
}
.hic-callout-warning .hic-callout-icon {
  color: var(--ot-warning);
}
.hic-callout-danger .hic-callout-icon {
  color: var(--ot-danger);
}
.hic-callout-info {
  border-color: color-mix(in srgb, var(--ot-primary) 45%, transparent);
  background: color-mix(in srgb, var(--ot-primary) 10%, transparent);
  color: var(--ot-text-primary);
}
.hic-details {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.hic-link {
  align-self: flex-start;
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--ot-primary);
  font-size: var(--ot-font-size-sm);
  font-family: inherit;
  cursor: pointer;
}
.hic-link-sm {
  font-size: var(--ot-font-size-xs);
}
.hic-grid {
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  background: var(--ot-bg-page);
  font-size: var(--ot-font-size-xs);
  overflow-x: auto;
}
.hic-grid-row {
  display: grid;
  grid-template-columns: 76px minmax(0, 1fr) minmax(0, 1fr);
  gap: 0 10px;
  padding: 6px 10px;
  align-items: start;
  overflow-wrap: anywhere;
}
.hic-grid-row + .hic-grid-row {
  border-top: 1px solid var(--ot-border-subtle);
}
.hic-grid-row .hic-label {
  width: auto;
}
.hic-grid-head {
  color: var(--ot-text-secondary);
}
.hic-mono {
  font-family: var(--ot-font-mono);
}
.hic-check {
  height: auto;
  white-space: normal;
  line-height: 1.55;
}
</style>
