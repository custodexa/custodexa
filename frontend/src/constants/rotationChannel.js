/**
 * 改密通道顯示中繼資料唯一事實源。
 *
 * 值域硬拷後端 `internal/model/asset_rotation_channel.go`（RotationChannel*／
 * WinrmScheme*／WinrmTLSMode* 常數）。label 譯文住 locale（enum.rotationChannel.*、
 * enum.winrmScheme.*、enum.winrmTlsMode.*），三語完備性由
 * constants/__tests__/enum-locale-completeness.spec.js 盯著。
 */
import { t } from '@/i18n'

/** 通道值域（不含「未設定」的空字串：空字串＝依協議推導，讀取端以 effective_rotation_channel 收口） */
export const ROTATION_CHANNEL_VALUES = ['posix_ssh', 'windows_winrm', 'windows_ssh', 'db_native', 'none']

export const WINRM_SCHEME_VALUES = ['http', 'https']

export const WINRM_TLS_MODE_VALUES = ['system', 'ca', 'insecure']

/** 連線方式推導的預設埠（後端 EffectiveWinrmPort：0 → 依 scheme） */
export const WINRM_DEFAULT_PORTS = { http: 5985, https: 5986 }

/** rdp 資產經 OpenSSH 改密時的預設埠（後端 EffectiveRotationSSHPort：0 → 22） */
export const ROTATION_SSH_DEFAULT_PORT = 22

/** 只有這兩種協議的資產可設定 Windows 通道（後端 RotationChannelCompatibleWith） */
export const ROTATION_CHANNEL_PROTOCOLS = ['rdp', 'ssh']

/** 可設「資料庫帳號自行改密」（db_native）的協議（後端 ProtocolType.SupportsQueryConsole；redis 不在內） */
export const DB_ROTATION_PROTOCOLS = ['mysql', 'postgres', 'mssql']

/**
 * 資料庫連線的加密檔位（硬拷後端 model.DBRotationTransportRisk 視為已加密的 TLS 模式）。
 * 只供表單在未存檔時即時判定；儲存後一律以伺服端回傳的 transmission_risks 為準。
 */
export const DB_ROTATION_ENCRYPTED_TLS_MODES = ['require', 'verify-ca', 'verify-full']

/** 資料庫改密以未加密連線進行的風險鍵（後端 model.RiskDBRotationUnencrypted） */
export const DB_ROTATION_RISK_KEY = 'db_rotation_unencrypted'

/**
 * 伺服端回傳的資產傳輸風險是否含「資料庫改密未加密」。不在前端以 TLS 檔位重算。
 * @param {{transmission_risks?: Array<{key?: string}>}} asset
 * @returns {boolean}
 */
export const hasDBRotationRisk = (asset) =>
  Array.isArray(asset?.transmission_risks) &&
  asset.transmission_risks.some((r) => r && r.key === DB_ROTATION_RISK_KEY)

/**
 * 由資產列表／詳情物件取得有效通道。
 * 後端列表投影帶 effective_rotation_channel；舊回應或單測替身缺該欄時，
 * 依後端 EffectiveRotationChannel 的同一規則推導（空字串：ssh → posix_ssh，其餘 → none）。
 * @param {{protocol?: string, rotation_channel?: string, effective_rotation_channel?: string}} asset
 * @returns {string}
 */
export const effectiveRotationChannel = (asset) => {
  if (!asset) return 'none'
  if (asset.effective_rotation_channel) return asset.effective_rotation_channel
  if (asset.rotation_channel) return asset.rotation_channel
  return asset.protocol === 'ssh' ? 'posix_ssh' : 'none'
}

/** 資產是否參與改密（改密計劃的資產下拉只列這些） */
export const isRotatableAsset = (asset) => effectiveRotationChannel(asset) !== 'none'

/**
 * 通道顯示文字：WinRM 附連線方式（HTTP／HTTPS）；資料庫帳號自改在伺服端判定
 * 未加密時附「未加密」；其餘直接取 enum 譯文。none 回空字串，由呼叫端決定佔位符。
 * withRisk=false 只回通道名：紀錄表的通道欄取資產現況，未加密由紀錄當時的標示表示。
 */
export const rotationChannelText = (asset, { withRisk = true } = {}) => {
  const channel = effectiveRotationChannel(asset)
  if (channel === 'none') return ''
  if (!ROTATION_CHANNEL_VALUES.includes(channel)) return channel
  const base = t(`enum.rotationChannel.${channel}`)
  if (channel === 'db_native') {
    return withRisk && hasDBRotationRisk(asset)
      ? `${base} · ${t('changeSecretPlans.channelUnencryptedSuffix')}`
      : base
  }
  if (channel !== 'windows_winrm') return base
  const scheme = asset.winrm_scheme || 'http'
  const schemeText = WINRM_SCHEME_VALUES.includes(scheme) ? t(`enum.winrmScheme.${scheme}`) : scheme
  return `${base} · ${schemeText}`
}

/**
 * 通道 tag 色：http 的 WinRM 與不驗證憑證的 https 走 warning（與傳輸階梯的風險鍵同向）；
 * 資料庫帳號自改在伺服端判定未加密時走 warning；其餘 info。
 */
export const rotationChannelTagType = (asset) => {
  const channel = effectiveRotationChannel(asset)
  if (channel === 'db_native') return hasDBRotationRisk(asset) ? 'warning' : 'info'
  if (channel !== 'windows_winrm') return 'info'
  if ((asset.winrm_scheme || 'http') === 'http') return 'warning'
  return asset.winrm_tls_mode === 'insecure' ? 'warning' : 'info'
}
