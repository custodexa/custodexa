// 帳號憑證庫的枚舉顯示中繼資料。
//
// 值域硬拷後端：
//   `backend/internal/model/credential.go`（範圍、協定族、成員狀態、輪替模式與狀態）
//   `backend/internal/modules/asset/credential_rotation.go`（聚合態五值）
//   `backend/internal/modules/asset/credential_rotation_split.go`（脫離來源）
// 完備性由 `constants/__tests__/credentials.spec.js` 把關——後端新增一個值而三語
// 沒跟上時那裡會紅，而不是畫面上靜默出現一個機器碼。

import { t } from '@/i18n'

/** 憑證範圍：專用（恰一個掛載）／共用（具名、可掛多台） */
export const CREDENTIAL_SCOPE_VALUES = ['dedicated', 'shared']

/** 秘密型別。K8s 的 token 也存在密碼欄，顯示層依協定族呈現，不另設值域 */
export const CREDENTIAL_SECRET_TYPE_VALUES = ['password', 'ssh_key']

/** 協定族：掛載時與資產協定比對相容性 */
export const CREDENTIAL_PROTOCOL_FAMILY_VALUES = ['ssh', 'windows', 'vnc', 'database', 'k8s']

/** 輪替模式：整組一起換／每台各自隨機 */
export const CREDENTIAL_ROTATION_MODE_VALUES = ['group', 'split']

/** 一次輪替的狀態 */
export const CREDENTIAL_ROTATION_STATUS_VALUES = ['running', 'completed', 'abandoned']

// 成員狀態七值。排列即「一台主機走過的順序」：排隊 → 改密中 → 已改未驗證 →
// 就位，另有等待重試與兩種終態。畫面上的統計列照這個順序讀下來
export const CREDENTIAL_MEMBER_STATE_VALUES = [
  'queued',
  'changing',
  'changed_unverified',
  'applied',
  'retry_wait',
  'terminal_failed',
  'abandoned',
]

// 聚合態五值（純投影，事實來源是逐成員狀態）。
// partial 先於 changing：一旦「有的已就位、有的還沒」，那就是要被看見的事實
export const CREDENTIAL_AGGREGATE_STATE_VALUES = [
  'idle',
  'queued',
  'changing',
  'partial',
  'out_of_sync',
]

/** 脫離共用時的新秘密來源 */
export const CREDENTIAL_DETACH_SOURCE_VALUES = ['random', 'custom']

// 成員狀態的標籤色。就位為 success、兩種失敗態為 danger、
// 已改未驗證為 warning（那台機器現在吃哪一組秘密不確定，是要人處理的狀態）；
// 排隊與改密中是「還說不上成不成」，一律中性
export const MEMBER_STATE_TAG_TYPE = {
  queued: 'info',
  changing: 'primary',
  changed_unverified: 'warning',
  applied: 'success',
  retry_wait: 'warning',
  terminal_failed: 'danger',
  abandoned: 'info',
}

/** 聚合態的標籤色。out_of_sync 是未收斂，需要人逐台補跑，故為 danger */
export const AGGREGATE_STATE_TAG_TYPE = {
  idle: 'info',
  queued: 'info',
  changing: 'primary',
  partial: 'warning',
  out_of_sync: 'danger',
}

/** 可補跑的成員狀態：只有這兩種終態允許逐台再試 */
export const RETRYABLE_MEMBER_STATES = ['terminal_failed', 'changed_unverified']

/** 密碼長度範圍（與改密計劃同一組界線） */
export const PASSWORD_LENGTH_MIN = 12
export const PASSWORD_LENGTH_MAX = 64
export const PASSWORD_LENGTH_DEFAULT = 16

// 專用憑證的顯示名是計算值（「資產名 / 帳號名」），而計算的兩個來源都可能缺席：
// 掛載的資產已被移除、或帳號名本來就是空的。缺席時投影會退成空字串，畫面上就
// 出現一列什麼都沒有的憑證——看的人無從判斷那是資料壞了還是自己看錯。
// 兩個位置各自補一句話，讓「缺什麼」直接寫在名字上。
export function credentialDisplayName(credential) {
  if (!credential) return ''
  if (credential.scope === CREDENTIAL_SCOPE_VALUES[1]) return credential.name || ''
  const username = credential.username || t('credentials.usernameUnset')
  const raw = credential.name || ''
  const sep = raw.lastIndexOf(' / ')
  // 資產不存在時投影退為帳號名本身（不含分隔符），故沒有分隔符即代表資產沒了
  const asset = sep >= 0 ? raw.slice(0, sep).trim() : ''
  return `${asset || t('credentials.assetRemoved')} / ${username}`
}
