// 封印相位的單一持有者。
//
// **問題**：`KEK_PROVIDER=ui` 的全新安裝，管理員開站 → 被導到登入頁 → 輸入帳密 →
// 得到「系統尚未解封，服務未上線」→ 然後就卡死了。`/unseal` 存在且封印期可達，
// 但沒有任何東西會把人送過去。ui 模式因此形同不可用。
//
// **本模組不是安全邊界**：封印的強制點在後端（非白名單路由一律 503），
// 這裡只回答「使用者該去哪一頁」。`/seal/status` 是後端恆註冊且不要求登入的端點，
// 任何人都取得到同樣的資訊；導離 `/unseal` 縮小的是**介面可及面**（不再有一個
// 可互動的對外解封表單），**不是**偵察面。不得宣稱它阻止探測。

// **探測走裸 axios、不經 api/request 攔截器**（沿 postRefresh 的既有理由，
// 再加一條）：(1) 攔截器見到封印機器碼會呼叫本模組導向，探測自己觸發導向即為
// 遞迴；(2) 探測失敗不該冒出全域 toast；(3) 最實際的一點——`api/request` 需要
// 本模組的 markSealed，本模組若回頭 import `api/seal` 就構成模組環，
// 而環在 bundler 下的求值順序不是我們能保證的東西。
import axios from 'axios'

// 解封頁的路徑（單一事實源：導覽守衛、攔截器與文案都指向同一個字面）
export const UNSEAL_PATH = '/unseal'
// 守衛攔下頁的路徑（同上，單一事實源）
export const INSTANCE_GUARD_PATH = '/instance-guard'

export const SEAL_PHASE_UNKNOWN = 'unknown'
export const SEAL_PHASE_SEALED = 'sealed'
export const SEAL_PHASE_UNSEALED = 'unsealed'
// 單實例守衛攔下：段 1 取鎖失敗，行程停在只開最小監聽的攔下模式。
// **與封印相位共用這一份快取**——兩者都由 `/seal/status` 一次回答，各自建一套
// 快取必然在同一次探測後得出不同結論並互踢（封印守衛的既有教訓）。
// 攔下期 `state` 仍是 `sealed`（服務確實未上線），故 halted 的判定看
// `instance_guard.state`，且**先於** sealed 判定——否則人會被送去一個
// 同樣打不通的解封頁。
export const SEAL_PHASE_HALTED = 'halted'

// 後端封印閘對非白名單路由回的機器碼；見到它即代表「現在是封印狀態」，
// 且此訊號**恆為最終權威**（涵蓋「使用者停留在頁面上時後端重啟而重新封印」）
export const SEAL_GATE_CODE = 'SEAL_SERVICE_SEALED'

let phase = SEAL_PHASE_UNKNOWN
// 進站探測的 single-flight：多條路由守衛同時觸發時只打一次 /seal/status
let probeInFlight = null

/** 目前相位（不觸發任何請求）。 */
export function getSealPhase() {
  return phase
}

/**
 * 由封印狀態端點的回應更新相位。
 *
 * 解封頁每次讀狀態與解封成功後都必須呼叫它——否則解封成功後點「前往登入」，
 * 守衛會以陳舊的 sealed 相位把人彈回 `/unseal`，變成新的鎖死。
 * @param {{state?: string}} status
 */
export function publishSealStatus(status) {
  const state = status?.state
  if (!state) return
  if (status?.instance_guard?.state === 'halted') {
    phase = SEAL_PHASE_HALTED
    return
  }
  phase = state === 'unsealed' ? SEAL_PHASE_UNSEALED : SEAL_PHASE_SEALED
}

/**
 * 由攔下端點的回應更新相位。
 *
 * 確認送出成功（或鎖自行釋放）後，本實例會接著跑完段 1 與段 2；此刻的封印相位
 * 是 sealed 或 unsealed 尚未可知，故 running 只**清掉** halted 而不猜測後續相位，
 * 由下一次導覽重新探測。少了這一步，攔下頁上的「前往登入」會被守衛以陳舊的
 * halted 相位彈回本頁——與解封頁修過的鎖死同型。
 * @param {{state?: string}} halt
 */
export function publishHaltStatus(halt) {
  const state = halt?.state
  if (!state) return
  if (state === 'halted') {
    phase = SEAL_PHASE_HALTED
    return
  }
  if (phase === SEAL_PHASE_HALTED) phase = SEAL_PHASE_UNKNOWN
}

/** 執行期訊號：收到封印機器碼即回到封印相位。 */
export function markSealed() {
  phase = SEAL_PHASE_SEALED
}

/** 測試用：重設為未知相位（模組層單例在測試間會殘留）。 */
export function resetSealPhase() {
  phase = SEAL_PHASE_UNKNOWN
  probeInFlight = null
}

/**
 * 取得相位；未知時探測一次。
 *
 * **探測失敗維持 unknown 並讓呼叫端放行**，不 fail-close：以探測失敗為由把人
 * 導去 `/unseal`，會讓一次短暫的後端不可用把**已解封**部署的全體使用者逐出應用，
 * 而該頁同樣讀不到狀態。放行的代價由執行期 503 訊號自我修正。
 * @returns {Promise<string>}
 */
export async function ensureSealPhase() {
  if (phase !== SEAL_PHASE_UNKNOWN) return phase
  if (!probeInFlight) {
    probeInFlight = axios
      // **逾時刻意短於 api/request 的 10 秒**：本探測擋在**首次導覽**之前，
      // 逾時多長就是後端不可用時使用者盯著白畫面多久。`/seal/status` 是段 1 的
      // 極簡 handler，正常情形以毫秒計；3 秒已遠超其需要，而 10 秒會讓一次
      // 後端當機把整個應用的首屏拖成十秒空白
      .get('/api/v1/seal/status', { timeout: 3000 })
      .then(({ data }) => {
        publishSealStatus(data)
        return phase
      })
      .catch(() => SEAL_PHASE_UNKNOWN)
      .finally(() => {
        probeInFlight = null
      })
  }
  return probeInFlight
}
