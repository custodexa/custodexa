<template>
  <div class="asciinema-player-wrapper">
    <!-- Player Container (always rendered) -->
    <div class="player-container">
      <div
        ref="playerRef"
        class="asciinema-player"
      />

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
      <p>{{ $t('asciiPlayer.loading') }}</p>
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
import * as AsciinemaPlayer from 'asciinema-player'
import 'asciinema-player/dist/bundle/asciinema-player.css'
import { t } from '@/i18n'

const props = defineProps({
  recordingUrl: {
    type: String,
    required: true,
  },
  width: {
    type: [String, Number],
    default: '100%',
  },
  height: {
    type: [String, Number],
    default: 'auto',
  },
  autoPlay: {
    type: Boolean,
    default: false,
  },
  // 初始定位秒數：null＝不定位（行為與改動前
  // 完全相同）。宣告式而非 expose 方法——變速走 dispose→重建，一次性方法呼叫
  // 會在重建時遺失，prop 則能在重建後重放定位意圖
  startAt: {
    type: Number,
    default: null,
  },
})

// start-at-applied：回報**實際**落點與是否被夾到可用末端。父層據此決定顯示
// 「已定位至該筆紀錄前後」還是「該時刻不在錄影涵蓋範圍內」——不由播放器擅自
// 靜默夾住裝作成功（誠實邊界第 2 條）
const emit = defineEmits(['start-at-applied'])

const playerRef = ref(null)
const loading = ref(true)
const error = ref(null)
const player = ref(null)
const isPlaying = ref(false)
const currentTime = ref(0)
const duration = ref(0)
const speed = ref(1)
// 拖曳進度條時為 true：暫停 interval 對 currentTime 的覆寫，否則滑桿被每 100ms
// 的播放位置彈回而拖不動／無法 seek。
const isSeeking = ref(false)

let updateInterval = null

// 本次掛載是否已回報過定位結果（避免變速重建時重複回報）
let startAtReported = false

// 有效的初始定位秒數：null／非有限數／負值一律視為「不定位」
const requestedStart = () => {
  const v = props.startAt
  return typeof v === 'number' && Number.isFinite(v) && v > 0 ? v : 0
}

// 依已知時長把定位夾進可用範圍並回報一次。時長未知（0）時不夾——
// 寧可照請求值 seek，也不要拿一個尚未載入的 0 把使用者丟回開頭
const applyStartAt = async (inst) => {
  const requested = requestedStart()
  if (requested <= 0 || startAtReported) return
  const dur = duration.value
  const clamped = dur > 0 && requested > dur
  const applied = clamped ? dur : requested
  try {
    await inst.seek(applied)
    currentTime.value = applied
  } catch (err) {
    console.error('[AsciinemaPlayer] 初始定位失敗:', err)
  }
  startAtReported = true
  emit('start-at-applied', { requested, applied, clamped, duration: dur })
}

// 綁定播放狀態事件（initPlayer 與變速重建共用）
const attachStateEvents = (inst) => {
  inst.addEventListener('playing', () => { isPlaying.value = true })
  inst.addEventListener('pause', () => { isPlaying.value = false })
  inst.addEventListener('ended', () => { isPlaying.value = false })
}

// Initialize player
const initPlayer = async () => {
  try {
    // 空 URL 守衛：recordingUrl 改為 async 取得（一次性 token），未就緒前勿初始化，
    // 否則 asciinema 會抓到 SPA index.html、JSON 解析失敗而渲染殘留錯誤層
    if (!props.recordingUrl) {
      return
    }

    loading.value = true
    error.value = null

    // 重建前先銷毀舊實例（URL 變更時避免 errored 實例殘留 DOM）
    if (player.value) {
      try {
        player.value.dispose()
      } catch { /* 忽略銷毀錯誤 */ }
      player.value = null
    }

    // Wait for next tick to ensure DOM is ready
    await nextTick()

    if (!playerRef.value) {
      throw new Error(t('player.containerNotReady'))
    }


    // Create player instance
    const playerInstance = AsciinemaPlayer.create(
      props.recordingUrl,
      playerRef.value,
      {
        cols: 80,
        rows: 24,
        autoPlay: false, // Always start paused to get duration
        loop: false,
        fit: 'width',
        terminalFontSize: 'small',
        controls: false, // Use custom controls
        // asciinema-player 3.x 無 runtime setSpeed，速度只能於建立時指定；
        // 變速由 handleSpeedChange 帶目前 speed 重建播放器
        speed: speed.value,
        // startAt 是 asciinema-player 3.x 的 core option（實碼 asciinema-player.js:6037）。
        // 舊註解宣稱「不支援 startAt」為誤，已訂正。此處先給一次，時長就緒後
        // 再由 applyStartAt 夾進可用範圍——只靠 core option 無法處理越界
        startAt: requestedStart(),
      }
    )

    player.value = playerInstance

    // Helper function to update duration
    const updateDuration = async () => {
      try {
        const dur = await playerInstance.getDuration()
        if (dur !== null && dur !== undefined && !isNaN(dur) && dur > 0) {
          duration.value = dur
          console.log('[AsciinemaPlayer] Duration loaded:', duration.value, 'seconds')
        }
      } catch (err) {
        console.error('[AsciinemaPlayer] Error getting duration:', err)
      }
    }

    // Listen for 'playing' event to get duration
    // For asciicast v2 format, duration is calculated during playback initialization
    playerInstance.addEventListener('playing', async () => {
      await updateDuration()
    })

    // Try to get duration immediately (may not be available for asciicast v2)
    await updateDuration()

    // If duration is still 0, start playback briefly to trigger duration calculation
    if (duration.value === 0) {
      try {
        // Start playback to load duration from asciicast v2 format
        await playerInstance.play()

        // Wait briefly for 'playing' event to fire and duration to be set
        await new Promise(resolve => setTimeout(resolve, 100))

        // Pause and reset if autoPlay is false
        if (!props.autoPlay) {
          await playerInstance.pause()
          // 起點：無定位請求時回 0（原行為），有請求時回定位點
          await playerInstance.seek(requestedStart())
          // isPlaying will be set by event listener
        }
      } catch (err) {
        console.error('[AsciinemaPlayer] Error during initialization:', err)
      }
    } else {
      // Duration was available immediately (asciicast v1 or v3 format)
      if (props.autoPlay) {
        await playerInstance.play()
        // isPlaying will be set by event listener
      }
    }

    // 時長已知後才夾定位並回報（越界須明示，不得靜默跳到結尾裝作成功）
    await applyStartAt(playerInstance)

    // Add event listeners for player state changes
    attachStateEvents(playerInstance)

    // Start update interval
    startUpdateInterval()

    loading.value = false
  } catch (err) {
    console.error('[AsciinemaPlayer] 初始化失敗:', err)
    error.value = err.message || t('player.initFailed')
    loading.value = false
  }
}

// Start update interval to track playback progress
const startUpdateInterval = () => {
  if (updateInterval) {
    clearInterval(updateInterval)
  }

  updateInterval = setInterval(async () => {
    // 使用者拖曳中：不覆寫 currentTime，讓滑桿跟著手走
    if (isSeeking.value || !player.value) {
      return
    }
    try {
      // getCurrentTime() returns a Promise
      const time = await player.value.getCurrentTime()
      currentTime.value = time
    } catch (err) {
      console.error('[AsciinemaPlayer] 更新狀態失敗:', err)
    }
  }, 100)
}

// Toggle play/pause
const togglePlay = async () => {
  if (!player.value) return

  try {
    if (isPlaying.value) {
      console.log('[AsciinemaPlayer] Pausing playback')
      await player.value.pause()
    } else {
      console.log('[AsciinemaPlayer] Starting playback')
      await player.value.play()
    }
    // isPlaying will be updated by event listeners
  } catch (err) {
    console.error('[AsciinemaPlayer] 播放控制失敗:', err)
    ElMessage.error(t('player.controlFailed'))
  }
}

// 使用者開始拖曳進度條：暫停 interval 覆寫，讓滑桿跟著手走
const onSliderInput = () => {
  isSeeking.value = true
}

// Seek to time（放開滑桿時觸發）
const handleSeek = async (value) => {
  if (!player.value) {
    isSeeking.value = false
    return
  }
  try {
    await player.value.seek(value)
    currentTime.value = value
  } catch (err) {
    console.error('[AsciinemaPlayer] 跳轉失敗:', err)
    ElMessage.error(t('player.seekFailed'))
  } finally {
    isSeeking.value = false
  }
}

// Change playback speed：asciinema-player 3.x 無 runtime setSpeed（startAt 則是有的，
// 見 create 選項處的訂正），故以新速度做「乾淨重建」（不走 initPlayer 的取時長 dance）
// 並精準 seek 回原位置，避免位置偏移。重建帶目前位置而非 props.startAt——
// 定位意圖在首次套用後即由使用者接手，重建須重放的是「當前位置」
const handleSpeedChange = async (value) => {
  const pos = currentTime.value // 先擷取，避免任何 await 後位置已跑掉
  const wasPlaying = isPlaying.value
  speed.value = value
  if (!player.value || !playerRef.value) return
  try {
    isSeeking.value = true // 重建期間暫停 interval 覆寫
    try { player.value.dispose() } catch { /* 忽略 */ }
    player.value = null
    await nextTick()
    const inst = AsciinemaPlayer.create(props.recordingUrl, playerRef.value, {
      cols: 80, rows: 24, autoPlay: false, loop: false, fit: 'width',
      terminalFontSize: 'small', controls: false, speed: value,
      startAt: pos,
    })
    player.value = inst
    attachStateEvents(inst)
    await inst.seek(pos) // 精準回到原位置
    currentTime.value = pos
    if (wasPlaying) {
      await inst.play()
    }
    startUpdateInterval()
  } catch (err) {
    console.error('[AsciinemaPlayer] 速度變更失敗:', err)
    ElMessage.error(t('asciiPlayer.speedChangeFailed'))
  } finally {
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
    console.error('[AsciinemaPlayer] 全螢幕切換失敗:', err)
    ElMessage.error(t('player.fullscreenFailed'))
  }
}

// Format time (seconds to MM:SS)
const formatTime = (seconds) => {
  // Handle invalid values
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

// Watch for URL changes：initPlayer 內會先 dispose 舊實例再重建（不在此處只置 null，
// 否則舊的 errored 實例 DOM 會殘留）
watch(() => props.recordingUrl, () => {
  if (updateInterval) {
    clearInterval(updateInterval)
  }
  startAtReported = false // 換錄影＝換一份時長，定位須重新套用與重新回報
  initPlayer()
})

// 定位請求變更（同一頁換不同錨點）：重播一次定位意圖
watch(() => props.startAt, async () => {
  if (!player.value) return
  startAtReported = false
  await applyStartAt(player.value)
})

// Lifecycle hooks
onMounted(async () => {
  // Wait for the next tick to ensure the DOM is fully rendered
  await nextTick()
  initPlayer()
})

onBeforeUnmount(() => {
  if (updateInterval) {
    clearInterval(updateInterval)
  }
  if (player.value) {
    try {
      player.value.dispose()
    } catch (err) {
      console.error('[AsciinemaPlayer] 清理失敗:', err)
    }
  }
})
</script>

<style scoped>
.asciinema-player-wrapper {
  width: 100%;
  background: var(--ot-terminal-bg);
  border-radius: 4px;
  overflow: hidden;
  position: relative;
}

.player-container {
  width: 100%;
  min-height: 400px;
}

.asciinema-player {
  width: 100%;
  min-height: 400px;
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
  background: var(--ot-terminal-bg);
  z-index: 10;
}

.player-loading {
  color: var(--ot-text-primary);
}

.player-loading p {
  margin-top: 20px;
  font-size: 16px;
  color: #999;
}

.player-error {
  color: var(--ot-text-primary);
}

.custom-controls {
  background: var(--ot-bg-elevated);
  padding: 12px 16px;
  border-top: 1px solid #3d3d3d;
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
  color: #999;
  min-width: 45px;
  text-align: center;
}

/* Fullscreen styles */
:fullscreen .asciinema-player-wrapper,
::backdrop {
  background: var(--ot-terminal-bg);
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
}
</style>
