<template>
  <PreservicePage
    :messages="statusMessages"
    tone="danger"
    right-class="halt-card"
  >
    <!-- 攔下期本頁是唯一可達頁面（攔下模式的路由樹只有 /health、/seal/status 與
         兩條 instance-guard 端點），故語言切換入口與解封頁同一版位。
         純前端，不受後端狀態影響 -->
    <template #lang>
      <div class="lang-switch">
        <el-dropdown @command="setLanguage">
          <span class="lang-switch-label">
            {{ LOCALE_LABELS[locale] }}
            <el-icon class="el-icon--right"><ChevronDown /></el-icon>
          </span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item
                v-for="l in SUPPORTED_LOCALES"
                :key="l"
                :command="l"
                :disabled="l === locale"
              >
                {{ LOCALE_LABELS[l] }}
              </el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </div>
    </template>

    <!-- 左欄：現在是什麼狀態、誰握著鎖、什麼不可逆 -->
    <template #left>
      <!-- 左欄跟著相位走：確認被接受（或鎖自行釋放）之後「已攔下／自 — 起／
           持鎖者／兩個實例同時執行會損壞資料」四件事**都已不成立**，
           把它們留在畫面上等於在服務已經起來之後還宣稱它沒起來 -->
      <header class="halt-header">
        <h1 class="halt-title">
          {{ isRunning ? $t('instanceGuard.halt.runningPageTitle') : $t('instanceGuard.halt.title') }}
        </h1>
        <p class="halt-subtitle">
          {{ isRunning ? $t('instanceGuard.halt.runningSubtitle') : $t('instanceGuard.halt.subtitle') }}
        </p>
      </header>

      <!-- 狀態列在 5/12 欄寬內只放三件事：徽章、起算、重新整理。
           重試週期另起一行——它跟著「自 … 起」擠在同一行時，重新整理會被推掉行 -->
      <div
        v-loading="statusLoading"
        class="status-row"
      >
        <el-tag
          :type="badgeType"
          effect="dark"
          class="state-badge"
          data-test="state-badge"
        >
          {{ badgeText }}
        </el-tag>
        <span
          v-if="metaText"
          class="status-meta"
          data-test="status-meta"
        >{{ metaText }}</span>
        <!-- 圖示鈕（帶可及名稱）：文字版在中英日三語下都會把狀態列推成兩行 -->
        <el-button
          v-if="!isRunning"
          text
          :loading="statusLoading"
          class="halt-refresh"
          :aria-label="$t('common.refresh')"
          :title="$t('common.refresh')"
          @click="refresh"
        >
          <el-icon><RotateCw /></el-icon>
        </el-button>
      </div>
      <p
        v-if="isHalted"
        class="status-retry"
        data-test="status-retry"
      >
        {{ retryText }}
      </p>

      <!-- 持鎖者卡：**三個欄位名不走 locale**——`application_name`／`pid`／
           `backend_start` 是資料庫的欄位名，操作者要拿它們與主機上的日誌逐字比對，
           翻譯過去就對不上了（i18n spec 明列技術識別字原樣保留）-->
      <div
        v-if="isHalted && holder"
        class="holder-card"
      >
        <p class="holder-caption">
          {{ $t('instanceGuard.halt.holder') }}
        </p>
        <dl class="holder-rows">
          <div>
            <dt>application_name</dt>
            <dd class="mono">
              {{ holder.application_name || '-' }}
            </dd>
          </div>
          <div>
            <dt>pid</dt>
            <dd class="mono">
              {{ holder.pid ?? '-' }}
            </dd>
          </div>
          <div>
            <dt>backend_start</dt>
            <dd class="mono">
              {{ holder.backend_start || '-' }}
            </dd>
          </div>
          <div>
            <dt>{{ $t('instanceGuard.halt.code') }}</dt>
            <dd
              class="mono holder-code"
              data-test="holder-code"
            >
              {{ holder.code || '-' }}
            </dd>
          </div>
        </dl>
        <p
          v-if="holder.fingerprint_source === 'unavailable'"
          class="holder-note"
        >
          {{ $t('instanceGuard.halt.fingerprintUnavailable') }}
        </p>
      </div>
      <p
        v-else-if="isHalted"
        class="holder-note"
      >
        {{ $t('instanceGuard.halt.holderUnknown') }}
      </p>

      <!-- 不可逆事實。與解封頁的遺失警語同一版位語義：左欄在文件順序上先於右欄，
           故它恆在確認表單之前 -->
      <div
        v-if="isHalted"
        class="risk-callout"
      >
        <el-icon class="risk-icon">
          <TriangleAlert />
        </el-icon>
        <div>
          <p class="risk-title">
            {{ $t('instanceGuard.halt.riskTitle') }}
          </p>
          <p class="risk-body">
            {{ $t('instanceGuard.halt.riskBody') }}
          </p>
        </div>
      </div>

      <p
        v-if="isHalted"
        class="halt-hint"
      >
        {{ $t('instanceGuard.halt.stopHint') }}
      </p>
    </template>

    <!-- 右欄：唯一要做的那件事 -->
    <template #right>
      <!-- 已啟動：服務真的答得出話了才顯示（見 script 的續啟動空窗說明） -->
      <template v-if="isRunning">
        <h2 class="section-title is-success">
          {{ $t('instanceGuard.halt.runningTitle') }}
        </h2>
        <p class="section-desc">
          {{ $t('instanceGuard.halt.runningDesc') }}
        </p>
        <el-button
          type="primary"
          class="submit-btn goto-login"
          @click="goLogin"
        >
          {{ $t('instanceGuard.halt.goLogin') }}
        </el-button>
      </template>

      <!-- 啟動中：確認被接受（或鎖自行釋放）之後，行程要跑完 migration 與
           其餘啟動步驟才會重新開埠。這段期間頁面既不該說「已啟動」，
           也不該把連不上當成錯誤 -->
      <template v-else-if="isStarting">
        <h2 class="section-title">
          {{ $t('instanceGuard.halt.startingTitle') }}
        </h2>
        <p
          class="section-desc"
          data-test="starting-desc"
        >
          {{ $t('instanceGuard.halt.startingDesc') }}
        </p>
        <div
          v-loading="true"
          class="starting-spinner"
        />
      </template>

      <template v-else>
        <h2 class="section-title is-danger">
          {{ $t('instanceGuard.halt.formTitle') }}
        </h2>
        <p class="section-desc">
          {{ $t('instanceGuard.halt.formDesc') }}
        </p>

        <div class="step">
          <div class="step-head">
            <span class="step-num">1</span>
            <span class="step-label">{{ $t('instanceGuard.halt.step1') }}</span>
          </div>
          <el-checkbox
            v-model="confirmedPrimaryDown"
            class="halt-confirm"
          >
            {{ $t('instanceGuard.halt.confirmCheckbox') }}
          </el-checkbox>
        </div>

        <div class="step">
          <div class="step-head">
            <span class="step-num">2</span>
            <span
              id="halt-code-label"
              class="step-label"
            >{{ $t('instanceGuard.halt.step2') }}</span>
          </div>
          <!-- 等寬：讀者要把左欄的碼逐字元抄過來，比例字型下 0/O、1/l 分不開 -->
          <el-input
            v-model="code"
            aria-labelledby="halt-code-label"
            class="code-input"
            spellcheck="false"
            autocomplete="off"
            :placeholder="$t('instanceGuard.halt.codePlaceholder')"
          />
        </div>

        <!-- 帳號＋密碼是一組而非單一控制項：用 role="group" 加 aria-labelledby，
             兩個輸入框各自帶 aria-label（placeholder 不是可及名稱） -->
        <div
          class="step"
          role="group"
          aria-labelledby="halt-admin-label"
        >
          <div class="step-head">
            <span class="step-num">3</span>
            <span
              id="halt-admin-label"
              class="step-label"
            >{{ $t('instanceGuard.halt.step3') }}</span>
          </div>
          <div class="field-row">
            <el-input
              v-model="username"
              class="admin-input"
              autocomplete="off"
              :aria-label="$t('instanceGuard.halt.usernamePlaceholder')"
              :placeholder="$t('instanceGuard.halt.usernamePlaceholder')"
            />
            <el-input
              v-model="password"
              class="admin-input"
              type="password"
              show-password
              autocomplete="off"
              :aria-label="$t('instanceGuard.halt.passwordPlaceholder')"
              :placeholder="$t('instanceGuard.halt.passwordPlaceholder')"
            />
          </div>
        </div>

        <!-- 失敗訊息就近顯示在按鈕上方，不走全域 toast：本頁是整個服務唯一的
             畫面，toast 飄走之後讀者沒有第二個地方可以回頭看 -->
        <p
          v-if="submitError"
          class="submit-error"
          role="alert"
          data-test="submit-error"
        >
          {{ submitError }}
        </p>

        <el-button
          type="danger"
          class="submit-btn"
          :loading="submitting"
          :disabled="submitDisabled"
          @click="submit"
        >
          {{ $t('instanceGuard.halt.submit') }}
        </el-button>
      </template>
    </template>
  </PreservicePage>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ChevronDown, RotateCw, TriangleAlert } from 'lucide-vue-next'
import { ackInstanceGuardHalt, getInstanceGuardHalt } from '@/api/instanceGuard'
import { getSealStatus } from '@/api/seal'
import { resolveApiError } from '@/api/error'
import { formatDateTime } from '@/utils/format'
import { publishHaltStatus, publishSealStatus } from '@/utils/sealPhase'
import PreservicePage from '@/components/PreservicePage.vue'
import { SUPPORTED_LOCALES, LOCALE_LABELS, setLanguage, t } from '@/i18n'

// 單實例守衛攔下頁。
//
// 這一頁取代的是「上主機讀日誌、抄 12 碼、改 .env、重啟」——在中斷處理中，
// 那是最難操作的一段。**不需登入**：攔下模式下段 2 未起，JWT 不可能存在；
// 授權由「重打當下持鎖者的確認碼」＋「管理員帳密」兩件事共同承擔。
//
// 頁面本身不做任何判定：碼是否相符、帳密是否正確、持鎖者有沒有變，
// 全由送出時的後端重查決定。前端 SHALL NOT 先比對左欄的碼與輸入值——
// 那會讓一個**過期**的碼在前端看起來仍然正確。

const router = useRouter()
const { locale } = useI18n()

// 輪詢週期的保底值：後端未給（或給 0）時不至於變成無限迴圈或每毫秒打一次
const DEFAULT_RETRY_SECONDS = 15

// 續啟動空窗的退避參數：首次 1 秒，每次乘 1.5，上限 8 秒。
// 空窗長度取決於 migration 與段 2 建構，沒有可預先知道的值，故用退避而非固定週期
const STARTUP_POLL_INITIAL_MS = 1000
const STARTUP_POLL_MAX_MS = 8000
const STARTUP_POLL_FACTOR = 1.5

// 相位未知（狀態讀取失敗）時的輪詢退避：首次 2 秒，每次乘 1.5，上限 30 秒。
// 讀不到狀態就不知道該用後端給的哪個週期，故自帶一組；後端恢復後第一次讀成功
// 即回到後端週期（見 syncPolling）
const UNKNOWN_POLL_INITIAL_MS = 2000
const UNKNOWN_POLL_MAX_MS = 30000
const UNKNOWN_POLL_FACTOR = 1.5

const status = ref({})
const statusLoading = ref(false)
const statusError = ref('')
const submitting = ref(false)
const submitError = ref('')

const confirmedPrimaryDown = ref(false)
const code = ref('')
const username = ref('')
const password = ref('')

let pollTimer = null
let startupTimer = null
let startupDelay = STARTUP_POLL_INITIAL_MS
let unknownDelay = UNKNOWN_POLL_INITIAL_MS

// **「已啟動」只認明確的 running**：狀態讀不到時 `state` 是空的，若以
// 「非 halted 即已啟動」判定，一次讀取失敗就會在畫面上宣稱服務已上線
//（左欄同時顯示讀取失敗，兩者互相矛盾）。未知狀態一律留在確認表單那一側。
// 三態：halted（可確認接手）／starting（續啟動空窗）／running（服務答得出話）。
// 未知狀態（讀取失敗）留在確認表單那一側，不歸入任何一端。
const starting = ref(false)
const serviceUp = ref(false)
const isRunning = computed(() => serviceUp.value)
const isStarting = computed(() => !serviceUp.value && starting.value)
const isHalted = computed(() => !starting.value && status.value.state === 'halted')
const holder = computed(() => status.value.holder || null)
const retrySeconds = computed(() => {
  const n = Number(status.value.retry_interval_seconds)
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_RETRY_SECONDS
})
const sinceText = computed(() =>
  t('instanceGuard.halt.since', {
    time: status.value.since ? formatDateTime(status.value.since) : '—',
  })
)
const retryText = computed(() =>
  t('instanceGuard.halt.retry', { n: retrySeconds.value })
)

// 已啟動的起算時間取自封印狀態的守衛欄位（本實例取得鎖的時刻），
// 不是攔下期的 `since`（那是被擋下的時刻）；取不到就不顯示，不拿舊值頂替
const startedAt = ref('')
const startedText = computed(() =>
  t('instanceGuard.halt.startedAt', { time: formatDateTime(startedAt.value) })
)

const badgeType = computed(() => {
  if (isRunning.value) return 'success'
  if (isStarting.value) return 'warning'
  return 'danger'
})
const badgeText = computed(() => {
  if (isRunning.value) return t('instanceGuard.halt.badgeRunning')
  if (isStarting.value) return t('instanceGuard.halt.badgeStarting')
  return t('instanceGuard.halt.badge')
})
const metaText = computed(() => {
  if (isRunning.value) return startedAt.value ? startedText.value : ''
  return sinceText.value
})

// 左欄的固定版位（PreservicePage 持有），目前只有一則：狀態讀不到。
// 送出類失敗就近顯示於按鈕旁，不進這裡——它們是對「剛才那個動作」的回應
const statusMessages = computed(() => {
  if (!statusError.value) return []
  return [
    {
      key: 'statusError',
      tone: 'warning',
      title: t('instanceGuard.halt.statusErrorTitle'),
      text: statusError.value,
    },
  ]
})

// 三要件齊全才可按（後端同樣三缺一即拒；前端只是不讓人白按一次）
const submitDisabled = computed(
  () =>
    !confirmedPrimaryDown.value ||
    !code.value.trim() ||
    !username.value ||
    !password.value
)

const applyStatus = (data) => {
  status.value = data || {}
  // 導覽守衛的相位來源：running 之後點「前往登入」不得被 halted 相位彈回本頁
  publishHaltStatus(status.value)
  if (status.value.state === 'running') beginStartup()
}

// 續啟動空窗。
//
// **這是一段連不上的時間，不是錯誤**：確認被接受（或鎖被釋放而自動取得）之後，
// 行程會關掉攔下期的最小監聽，跑完 migration 與其餘啟動步驟，才重新開同一個埠。
// 期間對任何端點的請求都是連線被拒——既不是 503，也不會回 `state=running`。
// 若把它當錯誤呈現，操作者會在「確認成功」的下一秒看到一則失敗訊息並以為砸了。
//
// 判準改為「服務答得出話」：以退避輪詢封印狀態端點，**沒有回應**視為仍在啟動；
// 拿到回應且守衛已不在攔下狀態，才轉「已啟動」。
const beginStartup = () => {
  if (starting.value) return
  starting.value = true
  submitError.value = ''
  statusError.value = ''
  stopHaltPolling()
  startupDelay = STARTUP_POLL_INITIAL_MS
  probeStartup()
}

const scheduleStartupProbe = () => {
  startupTimer = setTimeout(probeStartup, startupDelay)
  startupDelay = Math.min(Math.round(startupDelay * STARTUP_POLL_FACTOR), STARTUP_POLL_MAX_MS)
}

const probeStartup = async () => {
  startupTimer = null
  try {
    const sealStatus = await getSealStatus({ skipErrorToast: true })
    if (sealStatus?.instance_guard?.state === 'halted') {
      // 又回到攔下（例如鎖在續啟動途中再度被搶走）：回到確認表單，不假裝進行中
      starting.value = false
      publishSealStatus(sealStatus)
      await loadStatus()
      // 回到攔下就要恢復輪詢，否則這一頁自此不再自己更新
      syncPolling()
      return
    }
    serviceUp.value = true
    startedAt.value = sealStatus?.instance_guard?.since || ''
    publishSealStatus(sealStatus)
  } catch {
    // 連不上、逾時、5xx 一律視為「還在啟動」：這段空窗沒有可區分的訊號，
    // 而猜錯的代價是把一個正在正常啟動的實例報成故障
    scheduleStartupProbe()
  }
}

const loadStatus = async () => {
  statusLoading.value = true
  try {
    applyStatus(await getInstanceGuardHalt({ skipErrorToast: true }))
    statusError.value = ''
  } catch (error) {
    // 讀不到狀態不等於已啟動：明說讀取失敗，不覆蓋已知狀態
    statusError.value = resolveApiError(error.response?.data, error.response?.status)
  } finally {
    statusLoading.value = false
  }
}

const clearCredentials = () => {
  password.value = ''
}

const submit = async () => {
  submitting.value = true
  submitError.value = ''
  try {
    const result = await ackInstanceGuardHalt(
      {
        confirmed_primary_down: confirmedPrimaryDown.value,
        code: code.value.trim(),
        username: username.value,
        password: password.value,
      },
      { skipErrorToast: true }
    )
    // 接受：回應本身就是新的攔下狀態（state=running），不必再讀一次
    applyStatus(result)
  } catch (error) {
    const data = error.response?.data
    submitError.value = resolveApiError(data, error.response?.status)
    if (data?.code === 'INSTANCE_GUARD_HOLDER_CHANGED') {
      // 持鎖者已變更：後端在同一個回應裡帶回新的持鎖者與新碼（Meta 平鋪於頂層）。
      // 左欄換成新碼、清空重打欄——留著舊值會讓人再送一次同樣的碼
      status.value = {
        ...status.value,
        state: data.state || status.value.state,
        holder: data.holder || null,
        retry_interval_seconds:
          data.retry_interval_seconds ?? status.value.retry_interval_seconds,
      }
      code.value = ''
      submitError.value = t('instanceGuard.halt.holderChanged')
    } else if (data?.code === 'INSTANCE_GUARD_NOT_HALTED') {
      // 送出途中鎖已被本實例取得：轉進續啟動空窗，而不是留下一個錯誤訊息
      applyStatus({ ...status.value, state: 'running' })
    }
  } finally {
    submitting.value = false
    clearCredentials()
  }
}

const goLogin = () => router.push('/login')

const stopHaltPolling = () => {
  if (pollTimer) {
    clearTimeout(pollTimer)
    pollTimer = null
  }
}

// 輪詢：鎖被釋放後 watchdog 會自動取得，此時頁面要自己轉為「已啟動」，
// 不能讓人盯著一個永遠是「已攔下」的畫面。週期用後端給的重取週期。
//
// **相位未知（狀態讀取失敗）同樣要續輪**：後端在攔下期只開最小監聽，讀取失敗
// （含首次）是預期中的事。若此時停掉輪詢，後端恢復之後頁面會永遠停在舊畫面，
// 只能靠人重新整理。未知相位改以自帶的退避續輪，讀成功即回到後端給的週期。
//
// 用一次性 setTimeout 自我排程（不是 setInterval）：週期會隨相位改變，
// 且下一次要等這一次讀完才排，**任一時刻只有一個計時器**。
const syncPolling = () => {
  // 續啟動空窗與已啟動各有自己的路徑（probeStartup／不需再讀），此處收手
  if (starting.value || serviceUp.value) {
    stopHaltPolling()
    return
  }
  if (pollTimer) return
  let delay
  if (isHalted.value) {
    unknownDelay = UNKNOWN_POLL_INITIAL_MS
    delay = retrySeconds.value * 1000
  } else {
    delay = unknownDelay
    unknownDelay = Math.min(
      Math.round(unknownDelay * UNKNOWN_POLL_FACTOR),
      UNKNOWN_POLL_MAX_MS
    )
  }
  pollTimer = setTimeout(async () => {
    pollTimer = null
    await loadStatus()
    syncPolling()
  }, delay)
}

// 手動重新整理：讀完一律重新評估輪詢——輪詢若因轉入其他相位而停過，
// 這裡要能把它接回來，而不是讓人再按第二次
const refresh = async () => {
  await loadStatus()
  syncPolling()
}

onMounted(async () => {
  await loadStatus()
  syncPolling()
})

onUnmounted(() => {
  stopHaltPolling()
  if (startupTimer) clearTimeout(startupTimer)
  clearCredentials()
})

// 測試驅動用（happy-dom 下 timer 行為不穩）：狀態注入與提交入口
defineExpose({
  loadStatus,
  refresh,
  submit,
  status,
  code,
  confirmedPrimaryDown,
  username,
  password,
  starting,
  serviceUp,
})
</script>

<style scoped>
.starting-spinner {
  min-height: 60px;
}

/* 語言切換：版位與類名沿用解封頁（同為未登入的整頁畫面） */
.lang-switch-label {
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: var(--ot-space-xs);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.lang-switch-label:hover {
  color: var(--ot-primary);
}

.halt-title {
  margin: 0 0 var(--ot-space-xs);
  font-size: var(--ot-font-size-xl);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.halt-subtitle {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
  color: var(--ot-text-secondary);
}

.status-row {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  flex-wrap: wrap;
}

.status-meta {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

/* 重試週期：獨立一行的次要資訊，不參與狀態列的寬度預算 */
.status-retry {
  margin: -6px 0 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

/* 圖示鈕縮到與徽章同高，狀態列不因它變高 */
.halt-refresh {
  height: 24px;
  padding: 0 4px;
}

.holder-card {
  padding: var(--ot-space-sm) 14px;
  border: 1px solid var(--el-border-color);
  border-radius: var(--ot-radius-md);
  background: var(--el-fill-color-light);
}

.holder-caption {
  margin: 0 0 var(--ot-space-xs);
  font-size: var(--ot-font-size-sm);
  font-weight: 600;
  color: var(--ot-text-secondary);
}

/* 鍵在上、值在下的堆疊。
   左欄只有 5/12 欄寬，而這裡的值是**不可縮短的技術識別字**
  （`application_name` 由部署方設定、`backend_start` 是帶微秒的時間戳）：
   鍵值同列時值放不下，會從中間折成兩行，行高參差、最後一行只剩一兩個字元。
   堆疊之後每個值都獨佔一整欄寬，四列等高，抄碼時也不會看錯行 */
.holder-rows {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
  margin: 0;
  font-size: var(--ot-font-size-sm);
}

.holder-rows > div {
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.holder-rows dt {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.4;
}

.holder-rows dd {
  margin: 0;
  line-height: 1.4;
  /* 值仍可能超過一整欄寬（沒有空白可折的長字串）：容器內斷行，不撐破卡片 */
  overflow-wrap: anywhere;
}

/* 指紋類長字串沒有空白可折，逐字元斷 */
.mono {
  font-family: var(--ot-font-mono);
  word-break: break-all;
}

.holder-note {
  margin: var(--ot-space-xs) 0 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.risk-callout {
  display: flex;
  gap: 10px;
  align-items: flex-start;
  padding: var(--ot-space-sm) 14px;
  border: 1px solid var(--el-color-warning);
  border-radius: var(--ot-radius-md);
  background: var(--el-color-warning-light-9);
}

.risk-icon {
  flex-shrink: 0;
  margin-top: 2px;
  font-size: 20px;
  color: var(--el-color-warning);
}

.risk-title {
  margin: 0 0 2px;
  font-weight: 700;
  color: var(--el-color-warning);
}

.risk-body {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
}

.halt-hint {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
  color: var(--ot-text-secondary);
}

.section-title {
  margin: 0;
  font-size: var(--ot-font-size-lg);
  font-weight: 600;
}

.section-title.is-danger {
  color: var(--el-color-danger);
}

.section-title.is-success {
  color: var(--el-color-success);
}

.section-desc {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
  color: var(--ot-text-secondary);
}

.step {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
}

.step-head {
  display: flex;
  align-items: center;
  gap: 10px;
}

.step-num {
  width: 22px;
  height: 22px;
  flex-shrink: 0;
  border-radius: 50%;
  border: 1px solid var(--ot-primary);
  color: var(--ot-primary);
  font-size: var(--ot-font-size-xs);
  display: flex;
  align-items: center;
  justify-content: center;
}

.step-label {
  font-weight: 600;
}

.code-input :deep(.el-input__inner) {
  font-family: var(--ot-font-mono);
}

.field-row {
  display: flex;
  gap: var(--ot-space-sm);
}

.admin-input {
  flex: 1;
}

.submit-error {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  line-height: 1.5;
  color: var(--el-color-danger);
}

.submit-btn {
  width: 100%;
  margin-top: var(--ot-space-xs);
}

/* 承擔勾選的文字要能折行：英文一句超過右欄寬度時不得溢出卡片 */
.halt-confirm {
  height: auto;
  align-items: flex-start;
  white-space: normal;
}
.halt-confirm :deep(.el-checkbox__label) {
  white-space: normal;
  line-height: 1.5;
}
</style>
