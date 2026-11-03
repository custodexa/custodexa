<!--
  ExecutorLoginCheck：專用帳號區塊的「測試登入」狀態行，填進區塊的 login-status 插槽。

  一個框、一顆固定位置的按鈕：未測／過期（黃框）、測試中（中性框、按鈕停用）、成功（綠框）、
  失敗（紅框，下一步放在同一行）。按下後結果原地替換，不跳全域提示；
  測試登入是即時動作，不讀也不寫抽屜表單，所以不會讓抽屜進入「有未存修改」。

  props 即插槽參數：{ assetId, executor, revision, protocol, windowsFamily, hostKeyRecorded, actions }。
  完成（成功、失敗或被擋）後 emit done，供抽屜重讀主機金鑰（第一次登入會記下指紋）。
  按鈕標 data-focus="executor-test-login"，是深連結落點；測試期間按鈕以 aria-disabled 保留焦點（不用原生 disabled）；若焦點仍掉落，結果出來後回到按鈕。
-->
<template>
  <div
    v-if="loaded"
    class="login-check"
    data-test="login-check"
  >
    <div
      class="lc-box"
      :class="`is-${view.tone}`"
      role="status"
      aria-live="polite"
      data-test="login-check-box"
      :data-state="view.state"
    >
      <component
        :is="view.icon"
        :size="15"
        aria-hidden="true"
        class="lc-icon"
        :class="{ 'is-spin': view.state === 'testing' }"
        data-test="login-check-icon"
      />
      <div class="lc-main">
        <p
          class="lc-text"
          data-test="login-check-text"
        >
          <strong
            class="lc-head"
            data-test="login-check-head"
          >{{ view.head }}</strong>
          <span data-test="login-check-body-first">{{ bodyParts.first }}</span>
        </p>
        <p
          v-if="bodyParts.rest || view.setupLink"
          class="lc-text lc-rest"
          data-test="login-check-rest"
        >
          <span>{{ bodyParts.rest }}</span>
          <el-button
            v-if="view.setupLink"
            link
            type="primary"
            size="small"
            class="lc-link"
            data-test="login-check-setup"
            @click="openSetup($event)"
          >
            {{ t('assetExecutor.loginCheck.setupLink') }}
            <ExternalLink
              :size="12"
              aria-hidden="true"
              class="lc-ext"
            />
          </el-button>
        </p>
        <p
          v-if="view.second"
          class="lc-second"
          data-test="login-check-second"
        >
          {{ view.second }}
          <el-button
            v-if="view.secondLink"
            link
            type="primary"
            size="small"
            class="lc-link"
            data-test="login-check-read-setup"
            @click="openSetup($event)"
          >
            {{ t('assetExecutor.loginCheck.setupLink') }}
          </el-button>
        </p>
        <p
          v-if="view.rawCode"
          class="lc-second lc-code"
          data-test="login-check-raw-code"
        >
          {{ t('assetExecutor.loginCheck.unknown.code', { code: view.rawCode }) }}
        </p>
      </div>
      <div
        class="lc-actions"
        data-test="login-check-actions"
      >
        <el-button
          v-if="view.fix"
          v-preview-write
          type="primary"
          size="small"
          :disabled="busy"
          data-test="login-check-fix"
          @click="onFix($event)"
        >
          <KeyRound
            v-if="view.fix === 'keyPublic'"
            :size="13"
            aria-hidden="true"
            class="lc-btn-icon"
          />
          {{ view.fixLabel }}
          <ExternalLink
            v-if="view.fix === 'credential'"
            :size="12"
            aria-hidden="true"
            class="lc-ext"
          />
        </el-button>
        <el-button
          ref="btnRef"
          v-preview-write
          :type="view.state === 'untested' || busy ? 'primary' : undefined"
          size="small"
          :disabled="unsupported"
          :aria-disabled="busy ? 'true' : undefined"
          :aria-busy="busy ? 'true' : undefined"
          :class="{ 'is-busy': busy }"
          data-focus="executor-test-login"
          data-test="login-check-button"
          @click="run"
        >
          <LoaderCircle
            v-if="busy"
            :size="13"
            aria-hidden="true"
            class="lc-btn-icon is-spin"
          />
          <PlugZap
            v-else-if="view.state === 'untested'"
            :size="13"
            aria-hidden="true"
            class="lc-btn-icon"
          />
          {{ buttonLabel }}
        </el-button>
      </div>
    </div>
    <p
      v-if="unsupported"
      class="lc-note"
      data-test="login-check-unsupported"
    >
      {{ t('assetExecutor.loginCheck.unsupported') }}
    </p>
    <p
      v-if="httpError"
      class="lc-note lc-error"
      role="alert"
      data-test="login-check-error"
    >
      {{ httpError }}
    </p>
    <p
      v-if="showHostKeyNote"
      class="lc-note"
      data-test="login-check-hostkey-note"
    >
      {{ t('assetExecutor.loginCheck.hostKeyNote') }}
    </p>
  </div>
</template>

<script setup>
import { computed, nextTick, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { CircleCheck, CircleX, ExternalLink, KeyRound, LoaderCircle, PlugZap, TriangleAlert } from 'lucide-vue-next'
import { getExecutorLoginCheck, runExecutorLoginCheck } from '@/api/assetExecutor'
import { loginCheckResultView } from '@/constants/assetExecutor'
import { resolveApiError } from '@/api/error'
import { splitLead } from '@/utils/splitLead'
import { previewWrite as vPreviewWrite } from '@/directives/previewWrite'

const props = defineProps({
  assetId: { type: Number, required: true },
  executor: { type: Object, default: null },
  revision: { type: Number, default: 0 },
  protocol: { type: String, default: 'ssh' },
  windowsFamily: { type: Boolean, default: false },
  hostKeyRecorded: { type: Boolean, default: true },
  actions: { type: Object, required: true },
})
const emit = defineEmits(['done'])

const { t } = useI18n()

const loaded = ref(false)
const check = ref(null) // GET 或 POST 的回應：{ tested, stale, success, code, method, inventory_read, checked_at }
const busy = ref(false)
const httpError = ref('')
const btnRef = ref(null)
let loadToken = 0

// 平台不支援：RDP 與 Windows 族（非 POSIX 通道）
const unsupported = computed(() => props.protocol === 'rdp' || props.windowsFamily)
const account = computed(() => props.executor?.username || '')

async function loadState() {
  const token = ++loadToken
  if (unsupported.value) {
    loaded.value = true
    return
  }
  try {
    const res = await getExecutorLoginCheck(props.assetId)
    if (token !== loadToken) return
    check.value = res
  } catch {
    // 讀不到上次結果時當作沒測過，按鈕仍可用；不跳錯誤
    if (token !== loadToken) return
    check.value = null
  }
  loaded.value = true
}

// 換資產時清掉上一台的就地錯誤；只是區塊重讀（revision 變動）時保留，
// 「專用帳號已被換掉」的提示要在重讀之後仍看得到
watch(() => props.assetId, () => {
  httpError.value = ''
})
watch(() => [props.assetId, props.revision], loadState, { immediate: true })

// 狀態：testing／untested（含過期）／success／failed
const state = computed(() => {
  if (busy.value) return 'testing'
  const c = check.value
  if (!c || !c.tested || c.stale) return 'untested'
  return c.success ? 'success' : 'failed'
})

// MM-DD HH:mm；跨年才帶年份
function shortTime(iso) {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  const pad = (n) => String(n).padStart(2, '0')
  const md = `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
  return d.getFullYear() === new Date().getFullYear() ? md : `${d.getFullYear()}-${md}`
}

function untestedBody() {
  if (props.executor?.source === 'generate' && props.executor?.secret_type === 'ssh_key') {
    return t('assetExecutor.loginCheck.unconfirmed.key')
  }
  if (props.executor?.secret_type && props.executor.secret_type !== 'ssh_key') {
    return t('assetExecutor.loginCheck.unconfirmed.password')
  }
  return t('assetExecutor.loginCheck.unconfirmed.other')
}

const METHOD_KEYS = { executor_root: 'root', executor_sudo_password: 'password' }

const FIX_LABELS = {
  keyPublic: 'assetExecutor.getPublicKey',
  replace: 'assetExecutor.replace',
  hostKey: 'assetExecutor.loginCheck.fix.hostKey',
  credential: 'assetExecutor.loginCheck.fix.credential',
}

const view = computed(() => {
  const L = 'assetExecutor.loginCheck'
  const a = { account: account.value }
  switch (state.value) {
    case 'testing':
      return { state: 'testing', tone: 'neutral', icon: LoaderCircle, head: t(`${L}.testing.head`), body: t(`${L}.testing.body`, a) }
    case 'success': {
      const c = check.value
      const m = METHOD_KEYS[c.method] || 'nopasswd'
      const v = {
        state: 'success', tone: 'success', icon: CircleCheck,
        head: t(`${L}.success.head`),
        body: t(`${L}.success.${m}`, { ...a, time: shortTime(c.checked_at) }),
      }
      if (c.inventory_read === 'ok' || c.inventory_read === 'denied') {
        v.second = t(`${L}.inventoryRead.${c.inventory_read}`)
        v.secondLink = c.inventory_read === 'denied'
      }
      return v
    }
    case 'failed': {
      const c = check.value
      const row = loginCheckResultView(c.code, props.executor)
      if (!row) {
        return { state: 'failed', tone: 'danger', icon: CircleX, head: t(`${L}.unknown.head`), body: t(`${L}.unknown.body`), rawCode: c.code }
      }
      return {
        state: 'failed', tone: 'danger', icon: CircleX,
        head: t(`${L}.result.${row.key}.head`),
        body: t(`${L}.result.${row.key}.body`, a),
        setupLink: !!row.setupLink,
        fix: row.fix,
        fixLabel: row.fix ? t(FIX_LABELS[row.fix]) : '',
      }
    }
    default:
      return { state: 'untested', tone: 'warning', icon: TriangleAlert, head: t(`${L}.unconfirmed.head`), body: untestedBody() }
  }
})

// 失敗說明：第一句跟在粗體首句後，其餘（下一步、設定方式連結）另起一行，與畫面稿一致
const bodyParts = computed(() => {
  const { head, body } = splitLead(view.value.body)
  return { first: head, rest: body }
})

const buttonLabel = computed(() => {
  if (busy.value) return t('assetExecutor.loginCheck.testingButton')
  return t(view.value.state === 'untested' ? 'assetExecutor.loginCheck.button' : 'assetExecutor.loginCheck.retry')
})

// 沒有記錄過主機指紋時，這次登入會記下目前的指紋；判斷來源是插槽參數，不讀抽屜表單
const showHostKeyNote = computed(() => !props.hostKeyRecorded && !unsupported.value && props.protocol === 'ssh')

function btnEl() {
  return btnRef.value?.$el || null
}

async function restoreFocus(hadFocus) {
  await nextTick()
  const el = btnEl()
  const active = document.activeElement
  if (el && hadFocus && (!active || active === document.body || !active.isConnected)) el.focus()
}

async function run() {
  if (busy.value || unsupported.value) return
  const hadFocus = document.activeElement === btnEl()
  busy.value = true
  httpError.value = ''
  try {
    const res = await runExecutorLoginCheck(props.assetId)
    check.value = { ...res, tested: true, stale: false }
  } catch (err) {
    const data = err?.response?.data
    const status = err?.response?.status
    if (data?.code === 'RULE_EXECUTOR_STATE_CHANGED') {
      // 專用帳號在別處被換掉或清除：重讀區塊（插槽隨之重建），狀態行換成新帳號的狀態
      props.actions.reload?.()
    } else {
      httpError.value = resolveApiError(data, status)
    }
  } finally {
    busy.value = false
    emit('done')
    await restoreFocus(hadFocus)
  }
}

function onFix(ev) {
  const el = ev?.currentTarget || null
  switch (view.value.fix) {
    case 'keyPublic':
      props.actions.openPublicKey?.(el)
      break
    case 'replace':
      props.actions.openReplace?.()
      break
    case 'credential':
      props.actions.openCredential?.()
      break
    case 'hostKey': {
      const target = document.querySelector('.host-key-item')
      target?.scrollIntoView?.({ block: 'center' })
      target?.querySelector('button')?.focus?.()
      break
    }
    default:
  }
}

function openSetup(ev) {
  props.actions.openSetupHelp?.(ev?.currentTarget || null)
}

defineExpose({ run, state, check })
</script>

<style scoped>
.login-check {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
}

.lc-box {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  padding: var(--ot-space-sm) var(--ot-space-md) var(--ot-space-sm) var(--ot-space-sm);
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
  color: var(--ot-text-primary);
  border: 1px solid;
  border-radius: var(--ot-radius-md);
}

.lc-box.is-neutral {
  background-color: var(--ot-bg-elevated);
  border-color: var(--ot-border);
}

.lc-box.is-warning {
  background-color: color-mix(in srgb, var(--ot-warning) 10%, transparent);
  border-color: color-mix(in srgb, var(--ot-warning) 45%, transparent);
}

.lc-box.is-danger {
  background-color: color-mix(in srgb, var(--ot-danger) 18%, transparent);
  border-color: color-mix(in srgb, var(--ot-danger) 70%, transparent);
}

.lc-box.is-success {
  background-color: color-mix(in srgb, var(--ot-success) 8%, transparent);
  border-color: color-mix(in srgb, var(--ot-success) 45%, transparent);
}

.lc-icon {
  flex: none;
  align-self: flex-start;
  margin-top: 4px;
}

.is-neutral .lc-icon {
  color: var(--ot-primary);
}

.is-warning .lc-icon {
  color: var(--ot-warning);
}

.is-danger .lc-icon,
.is-danger .lc-head {
  color: var(--ot-danger);
}

.is-success .lc-icon,
.is-success .lc-head {
  color: var(--ot-success);
}

.is-spin {
  animation: lc-spin 1s linear infinite;
}

@keyframes lc-spin {
  to {
    transform: rotate(360deg);
  }
}

@media (prefers-reduced-motion: reduce) {
  .is-spin {
    animation: none;
  }
}

.lc-main {
  flex: 1;
  min-width: 0;
}

.lc-text,
.lc-second {
  margin: 0;
}

.lc-head {
  margin-right: var(--ot-space-sm);
}

.lc-rest {
  margin-top: 2px;
}

.lc-second {
  margin-top: 2px;
  color: var(--ot-text-secondary);
}

.lc-code {
  font-family: var(--ot-font-mono, monospace);
}

.lc-actions {
  display: flex;
  flex: none;
  gap: var(--ot-space-sm);
  align-items: center;
}

.lc-actions .el-button + .el-button {
  margin-left: 0;
}

/* 測試進行中不用原生 disabled（會讓焦點掉到 body），改以 aria-disabled 保留焦點；點擊在 run() 內被擋下 */
/* 測試中的按鈕是主要樣式的降階版（較深的藍底），不是 plain 的淺色 */
.lc-actions .el-button.is-busy {
  cursor: progress;
  opacity: 0.55;
}

.lc-btn-icon {
  margin-right: 4px;
}

.lc-link {
  vertical-align: baseline;
}

.lc-ext {
  margin-left: 3px;
}

.lc-note {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.lc-error {
  color: var(--ot-danger);
}
</style>
