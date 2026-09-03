<template>
  <div class="guacamole-player-wrapper">
    <!-- Player Container -->
    <div class="player-container">
      <div
        ref="playerRef"
        class="guacamole-display"
      />

      <!-- 定位中：錄影須整檔解析出 frames 才 seek 得動，這段期間畫面仍在開頭，
           不標示會被讀成「這就是那一刻」 -->
      <div
        v-if="startAtPending && !error"
        class="seek-pending"
        data-test="guac-seek-pending"
      >
        <el-icon class="is-loading">
          <LoaderCircle />
        </el-icon>
        <span>{{ $t('guacPlayer.seeking') }}</span>
      </div>

      <!-- Custom Controls -->
      <div
        v-show="!loading && !error"
        class="custom-controls"
      >
        <div class="control-row">
          <!-- Play/Pause Button -->
          <el-button
            :icon="isPlaying ? CirclePause : CirclePlay"
            size="small"
            @click="togglePlay"
          >
            {{ isPlaying ? $t('player.pause') : $t('player.play') }}
          </el-button>

          <!-- Progress Slider -->
          <div class="progress-slider">
            <span class="time-display">{{ formatTime(currentTime) }}</span>
            <el-slider
              v-model="currentTime"
              :max="duration"
              :step="0.1"
              :show-tooltip="false"
              @input="onSliderInput"
              @change="handleSeek"
            />
            <span class="time-display">{{ formatTime(duration) }}</span>
          </div>

          <!-- Speed Control -->
          <el-select
            v-model="speed"
            size="small"
            style="width: 90px"
            @change="handleSpeedChange"
          >
            <el-option
              label="0.5x"
              :value="0.5"
            />
            <el-option
              label="1x"
              :value="1"
            />
            <el-option
              label="2x"
              :value="2"
            />
            <el-option
              label="4x"
              :value="4"
            />
            <el-option
              label="8x"
              :value="8"
            />
          </el-select>

          <!-- Fullscreen Toggle -->
          <el-button
            :icon="Maximize"
            size="small"
            @click="toggleFullscreen"
          >
            {{ $t('player.fullscreen') }}
          </el-button>
        </div>
      </div>
    </div>

    <!-- Loading Overlay -->
    <div
      v-if="loading"
      class="player-overlay player-loading"
    >
      <el-icon
        class="is-loading"
        :size="40"
      >
        <LoaderCircle />
      </el-icon>
      <p>{{ $t('guacPlayer.loading') }}</p>
    </div>

    <!-- Error Overlay -->
    <div
      v-if="error"
      class="player-overlay player-error"
    >
      <el-result
        icon="error"
        :title="$t('player.loadFailedTitle')"
        :sub-title="error"
      >
        <template #extra>
          <el-button
            type="primary"
            @click="retryLoad"
          >
            {{ $t('player.reload') }}
          </el-button>
        </template>
      </el-result>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onBeforeUnmount, watch, nextTick } from 'vue'
import { ElMessage } from 'element-plus'
import { LoaderCircle, CirclePlay, CirclePause, Maximize } from 'lucide-vue-next'
import { t } from '@/i18n'
import { getAccessToken } from '@/utils/session'

// 使用全局 Guacamole 對象（由 index.html 中的 guacamole-1.5.5.min.js 提供）
const Guacamole = window.Guacamole

const props = defineProps({
  recordingUrl: {
    type: String,
    required: true,
  },
  autoPlay: {
    type: Boolean,
    default: false,
  },
  // 初始定位秒數：null＝不定位。
  // **不可在載入完成前下 seek**——SessionRecording 的 seek 在 frames 尚空時是
  // no-op（guacamole-common.js:`this.seek=function(b,d){if(0!==c.length)...`），
  // 靜默失敗會讓畫面停在開頭卻顯示「已定位」
  startAt: {
    type: Number,
    default: null,
  },
})

const emit = defineEmits(['start-at-applied'])

const playerRef = ref(null)
const loading = ref(true)
const error = ref(null)
const recording = ref(null)
const isPlaying = ref(false)
const currentTime = ref(0)
const duration = ref(0)

let updateInterval = null
// 牆鐘平滑進度（guac 錄像幀稀疏時 getPosition 只回目前幀時間戳、靜態幀間會凍住再跳）：
// 以播放起點的實際位置 + 經過的牆鐘時間內插，使進度條與時間在靜態期仍平滑前進。
let playBaseMs = 0
let playStartWall = 0
// 使用者拖曳進度條時為 true：暫停 interval 對 currentTime 的覆寫，否則滑桿會被每 100ms
// 的播放位置彈回、導致拖不動／無法 seek。
const isSeeking = ref(false)

// 倍速：guacamole-common-js 無 playbackRate。
// speed=1 走原生 play()（行為零變更）；speed≠1 走 scrub 引擎——暫停原生播放，
// 以「錨定位置 + 經過牆鐘 × 倍率」每 150ms 驅動 seek(target)，seek 未完成則跳過該 tick。
const speed = ref(1)
let scrubTimer = null
let scrubSeekInFlight = false
// 為 scrub 而暫停原生播放時，onpause 不得把 UI 置為暫停
let suppressPauseEvent = false

// ---- 初始定位（startAt）----
// 錄影以 Blob 整檔載入後才逐段解析出 frames；解析過程由 onprogress 回報「已解析到
// 第幾毫秒」，全部解析完才觸發 onload。定位分兩段落地：
//   onprogress 已越過目標 → 立即 seek（不必等整檔解析完，體感快）
//   onload 時仍未套用    → 目標超過總時長，夾到末端並回報 clamped
// 兩段都只跑一次（startAtApplied 閘）
const startAtApplied = ref(false)
// 定位中：有定位請求但尚未落地。供 UI 呈現「定位中」，避免使用者以為畫面就是那一刻
const startAtPending = ref(false)
// 本次定位的序號：seek 進行中若被另一次 seek 取消（guacamole 的 `cancel()` 會提前
// 呼叫前一個 callback），舊 callback 讀到的位置不是這次定位的落點，必須丟棄
let startAtSeekToken = 0

// 已解析出的幀時間戳（毫秒，錄影自身時間軸）。guacamole 的 onprogress 第一引數即
// `getDuration()`＝剛推入的那一幀的相對時間戳，故逐次記下即可零成本得到全部幀時刻。
// 用途見 frameAtOrBefore：錄影是稀疏幀，必須自己挑幀，不能把目標秒數丟給 seek。
let frameTimestampsMs = []

const requestedStartMs = () => {
  const v = props.startAt
  return typeof v === 'number' && Number.isFinite(v) && v > 0 ? Math.round(v * 1000) : 0
}

// 目標時刻之前（含當下）最接近的一幀。null＝尚無任何幀。
//
// **為什麼不直接 seek(目標)**：`.guac` 是稀疏幀——RDP 畫面靜止時 guacd 不寫幀，
// 實測有 26.5 秒完全無幀的空檔。guacamole 的 `SessionRecording.seek` 內部是一支
// 二分搜尋（`q=function F(a,b,d)`），目標落進空檔時會落到空檔**尾端的那一幀**，
// 也就是目標時刻**之後**（實測 t=10 落在 30.574s，偏 +20.57s）。落在之後代表
// 目標事件可能已經播過去，正是本 change 為文字終端修掉的那個危害。
// 故一律自己挑「目標之前最近的一幀」：寧早勿晚，且該幀畫面即目標時刻的畫面
// （其後至目標之間錄影沒有新畫面，否則就會有幀）。
const frameAtOrBefore = (targetMs) => {
  let picked = null
  for (const ts of frameTimestampsMs) {
    if (ts <= targetMs && (picked === null || ts > picked)) picked = ts
  }
  return picked
}

// final=true 代表 onload（整檔已解析，getDuration 為最終值）
const tryApplyStartAt = (parsedMs, final) => {
  const targetMs = requestedStartMs()
  if (targetMs <= 0 || startAtApplied.value || !recording.value) return
  const totalMs = final ? recording.value.getDuration() : parsedMs
  if (!final && totalMs < targetMs) return // 尚未解析到目標，seek 會是 no-op

  const clamped = final && targetMs > totalMs
  const beforeMs = frameAtOrBefore(targetMs)
  // 越界→夾到末端；否則取目標之前最近的一幀（無幀資訊時退回目標值，行為不劣於改動前）
  const seekMs = clamped ? totalMs : beforeMs === null ? targetMs : beforeMs
  startAtApplied.value = true
  const token = ++startAtSeekToken
  recording.value.seek(seekMs, () => {
    if (token !== startAtSeekToken) return // 已被後續定位取代，這個位置不是我們的落點
    // **回報實際落點，不是請求值**：seek 落在哪一幀由播放器決定，介面必須說出
    // 播放器真正停在的位置，否則就是對稽核宣稱一個播放器並不在的時刻。
    const actualMs =
      typeof recording.value?.getPosition === 'function' ? recording.value.getPosition() : seekMs
    playBaseMs = actualMs
    playStartWall = Date.now()
    currentTime.value = actualMs / 1000
    startAtPending.value = false
    emit('start-at-applied', {
      requested: targetMs / 1000,
      applied: actualMs / 1000,
      clamped,
      duration: totalMs / 1000,
    })
  })
}

// Initialize player
const initPlayer = async () => {
  try {
    loading.value = true
    error.value = null
    startAtApplied.value = false
    startAtPending.value = requestedStartMs() > 0
    frameTimestampsMs = [] // 換一份錄影＝換一組幀時刻

    console.log('[GuacamolePlayer] 初始化播放器:', props.recordingUrl)

    // Wait for next tick to ensure DOM is ready
    await nextTick()

    if (!playerRef.value) {
      throw new Error(t('player.containerNotReady'))
    }

    // Fetch recording file as Blob
    console.log('[GuacamolePlayer] 正在獲取錄製檔案...')
    const response = await fetch(props.recordingUrl, {
      headers: {
        'Authorization': `Bearer ${getAccessToken()}`,
      },
    })

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`)
    }

    const blob = await response.blob()
    console.log('[GuacamolePlayer] 錄製檔案已載入:', blob.size, 'bytes')

    // Create SessionRecording instance with Blob
    const rec = new Guacamole.SessionRecording(blob)
    recording.value = rec

    console.log('[GuacamolePlayer] SessionRecording 實例已創建')

    // Setup event listeners
    setupEventListeners()

    // Get display and append to container
    const display = rec.getDisplay()
    const element = display.getElement()

    // Clear container and append element
    playerRef.value.innerHTML = ''
    playerRef.value.appendChild(element)
    console.log('[GuacamolePlayer] 顯示元素已添加到 DOM')

    // Start update interval
    startUpdateInterval()

    loading.value = false

    // Auto play if enabled
    if (props.autoPlay) {
      await rec.play()
    }
  } catch (err) {
    console.error('[GuacamolePlayer] 初始化失敗:', err)
    error.value = err.message || t('player.initFailed')
    loading.value = false
  }
}

// Setup event listeners
const setupEventListeners = () => {
  if (!recording.value) return

  // onload event
  recording.value.onload = () => {
    console.log('[GuacamolePlayer] Recording loaded')

    // Get duration
    const dur = recording.value.getDuration()
    duration.value = dur / 1000 // Convert to seconds for slider
    console.log('[GuacamolePlayer] Duration:', duration.value, 'seconds')

    // 最終定位機會：到這裡還沒套用，代表目標超過總時長 → 夾到末端並回報越界
    tryApplyStartAt(dur, true)
  }

  // onprogress：解析進度回報（第一引數為「已解析到的時長」毫秒，即剛推入的那一幀的
  // 時間戳）。逐次記下幀時刻供 frameAtOrBefore 挑幀；一旦越過目標時刻即可 seek，
  // 不必等整檔解析完
  recording.value.onprogress = (parsedMs) => {
    if (Number.isFinite(parsedMs)) frameTimestampsMs.push(parsedMs)
    tryApplyStartAt(parsedMs, false)
  }

  // onplay event：記下播放起點（實際位置 + 牆鐘），供 updateInterval 內插
  recording.value.onplay = () => {
    console.log('[GuacamolePlayer] Playing')
    isPlaying.value = true
    playBaseMs = recording.value.getPosition()
    playStartWall = Date.now()
  }

  // onpause event（scrub 模式為驅動 seek 而暫停原生播放時不動 UI 狀態）
  recording.value.onpause = () => {
    console.log('[GuacamolePlayer] Paused')
    if (suppressPauseEvent) {
      suppressPauseEvent = false
      return
    }
    isPlaying.value = false
  }

  // onseek/onprogress：播放中每幀都會以「目前幀時間戳」回呼（跳動值），
  // 不在此覆寫 currentTime——播放中由 updateInterval 牆鐘內插、使用者 seek 由 handleSeek 設值。
  // 僅在非播放狀態（純載入/seek 過程）反映實際位置，避免進度條凍住再跳。
  recording.value.onseek = (position) => {
    if (!isPlaying.value) {
      currentTime.value = position / 1000
    }
  }

  // onerror event
  recording.value.onerror = (message) => {
    console.error('[GuacamolePlayer] Error:', message)
    error.value = message || t('guacPlayer.playbackError')
    loading.value = false
    ElMessage.error(t('guacPlayer.playbackErrorDetail', { message }))
  }
}

// Start update interval
const startUpdateInterval = () => {
  if (updateInterval) {
    clearInterval(updateInterval)
  }

  updateInterval = setInterval(() => {
    // 使用者拖曳中：不覆寫 currentTime，讓滑桿跟著手走
    if (isSeeking.value || !recording.value || !recording.value.isPlaying) {
      return
    }
    if (!recording.value.isPlaying()) {
      return
    }
    // 以錄像實際位置(getPosition，幀時間戳)為錨；幀變動時重錨，使進度永遠跟著畫面
    // （含 seek 後 guacamole 立即渲染第一幀而跳過大空檔的情形）。幀間以牆鐘平滑前進，
    // 使 real-time 靜態空檔期間進度仍動、不凍住。
    const recPos = recording.value.getPosition()
    if (recPos !== playBaseMs) {
      playBaseMs = recPos
      playStartWall = Date.now()
    }
    const durMs = duration.value * 1000
    let posMs = playBaseMs + (Date.now() - playStartWall)
    if (durMs > 0 && posMs >= durMs) {
      posMs = durMs
      recording.value.pause() // 播放到底自動暫停
    }
    currentTime.value = posMs / 1000
  }, 100)
}

// ---- scrub 倍速引擎（speed ≠ 1） ----
const startScrub = () => {
  stopScrub()
  playBaseMs = currentTime.value * 1000
  playStartWall = Date.now()
  isPlaying.value = true
  scrubTimer = setInterval(() => {
    if (!recording.value || isSeeking.value || scrubSeekInFlight) return
    const durMs = duration.value * 1000
    let target = playBaseMs + (Date.now() - playStartWall) * speed.value
    if (durMs > 0 && target >= durMs) {
      target = durMs
      stopScrub()
      isPlaying.value = false
    }
    currentTime.value = target / 1000
    scrubSeekInFlight = true
    recording.value.seek(Math.round(target), () => {
      scrubSeekInFlight = false
    })
  }, 150)
}

const stopScrub = () => {
  if (scrubTimer) {
    clearInterval(scrubTimer)
    scrubTimer = null
  }
}

// Toggle play/pause
const togglePlay = async () => {
  if (!recording.value) return

  try {
    if (isPlaying.value) {
      console.log('[GuacamolePlayer] Pausing playback')
      if (speed.value !== 1) {
        stopScrub()
        isPlaying.value = false
      } else {
        recording.value.pause()
      }
    } else {
      console.log('[GuacamolePlayer] Starting playback, speed =', speed.value)
      if (speed.value !== 1) {
        startScrub()
      } else {
        recording.value.play()
      }
    }
  } catch (err) {
    console.error('[GuacamolePlayer] 播放控制失敗:', err)
    ElMessage.error(t('player.controlFailed'))
  }
}

// 變更倍率：重錨目前位置，依新舊模式切換引擎；播放/暫停狀態不變
const handleSpeedChange = (value) => {
  if (!recording.value) return
  const wasPlaying = isPlaying.value
  playBaseMs = currentTime.value * 1000
  playStartWall = Date.now()
  if (!wasPlaying) return
  if (value === 1) {
    stopScrub()
    recording.value.play() // onplay 重錨牆鐘內插
  } else {
    if (recording.value.isPlaying()) {
      suppressPauseEvent = true
      recording.value.pause()
    }
    startScrub()
  }
}

// 使用者開始拖曳進度條：標記 seeking，暫停 interval 覆寫（讓滑桿跟著手走）
const onSliderInput = () => {
  isSeeking.value = true
}

// Seek to time（放開滑桿時觸發）
const handleSeek = async (value) => {
  if (!recording.value) {
    isSeeking.value = false
    return
  }

  try {
    const positionMs = Math.round(value * 1000) // Convert seconds to milliseconds
    // 重設牆鐘基準：若正在播放，內插從新位置接續（否則會跳回 seek 前）
    playBaseMs = positionMs
    playStartWall = Date.now()
    currentTime.value = value
    recording.value.seek(positionMs, () => {
      // seek 完成後才解除，避免 seek 期間 interval 又覆寫
      isSeeking.value = false
    })
  } catch (err) {
    console.error('[GuacamolePlayer] 跳轉失敗:', err)
    ElMessage.error(t('player.seekFailed'))
    isSeeking.value = false
  }
}

// Toggle fullscreen
const toggleFullscreen = () => {
  if (!playerRef.value) return

  try {
    if (!document.fullscreenElement) {
      playerRef.value.parentElement.requestFullscreen()
    } else {
      document.exitFullscreen()
    }
  } catch (err) {
    console.error('[GuacamolePlayer] 全螢幕切換失敗:', err)
    ElMessage.error(t('player.fullscreenFailed'))
  }
}

// Format time (seconds to MM:SS)
const formatTime = (seconds) => {
  if (seconds === null || seconds === undefined || isNaN(seconds)) {
    return '00:00'
  }

  const mins = Math.floor(seconds / 60)
  const secs = Math.floor(seconds % 60)
  return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`
}

// Retry loading
const retryLoad = () => {
  initPlayer()
}

// 定位請求變更：整檔已解析完，可直接落地（frames 已備，seek 不會是 no-op）
watch(() => props.startAt, () => {
  if (!recording.value || requestedStartMs() <= 0) return
  startAtApplied.value = false
  startAtPending.value = true
  tryApplyStartAt(recording.value.getDuration(), true)
})

// Watch for URL changes
watch(() => props.recordingUrl, () => {
  if (recording.value) {
    // Cleanup old recording
    stopScrub()
    if (updateInterval) {
      clearInterval(updateInterval)
    }
    recording.value = null
  }
  initPlayer()
})

// Lifecycle hooks
onMounted(async () => {
  await nextTick()
  initPlayer()
})

onBeforeUnmount(() => {
  stopScrub()
  if (updateInterval) {
    clearInterval(updateInterval)
  }
  if (recording.value) {
    try {
      recording.value.pause()
    } catch (err) {
      console.error('[GuacamolePlayer] 清理失敗:', err)
    }
  }
})
</script>

<style scoped>
.guacamole-player-wrapper {
  width: 100%;
  background: #ffffff;
  border-radius: 4px;
  overflow: hidden;
  /* 創建 Stacking Context 托住 Guacamole Canvas (z-index: -1) */
  position: relative;
  z-index: 0;
}

.player-container {
  width: 100%;
  min-height: 600px;
}

.guacamole-display {
  width: 100%;
  min-height: 600px;
  background: #ffffff;
  /* 創建 Stacking Context 托住 Guacamole Canvas (z-index: -1) */
  position: relative;
  z-index: 0;
}

.player-overlay {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  background: #ffffff;
  z-index: 10;
}

.player-loading {
  color: #333;
}

.player-loading p {
  margin-top: 20px;
  font-size: 16px;
  color: #666;
}

.player-error {
  color: #333;
}

.custom-controls {
  background: var(--ot-terminal-bg);
  padding: 12px 16px;
  border-top: 1px solid #e0e0e0;
}

.seek-pending {
  position: absolute;
  top: 12px;
  left: 12px;
  z-index: 11;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 12px;
  border-radius: 4px;
  background: rgba(0, 0, 0, 0.65);
  color: #fff;
  font-size: 13px;
}

.control-row {
  display: flex;
  align-items: center;
  gap: 12px;
}

.progress-slider {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 8px;
}

.time-display {
  font-size: 12px;
  color: #666;
  min-width: 45px;
  text-align: center;
}

/* Fullscreen styles */
:fullscreen .guacamole-player-wrapper,
::backdrop {
  background: #ffffff;
}

/* Make player responsive */
@media (max-width: 768px) {
  .control-row {
    flex-wrap: wrap;
  }

  .progress-slider {
    order: -1;
    width: 100%;
    margin-bottom: 8px;
  }

  .guacamole-display {
    min-height: 400px;
  }

  .player-container {
    min-height: 400px;
  }
}
</style>
