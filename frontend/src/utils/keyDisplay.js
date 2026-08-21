// env 側金鑰名稱/說明的查譯（i18n-backend-labels 模式）：錨後端穩定機器碼
// name_code / note_code，當前語言命中才譯，否則降級後端 zh 字串（wire fallback）。
import { t } from '@/i18n'
import { translated, warnMissingTranslation } from '@/utils/i18nDisplay'

// keyEnvName env 金鑰名稱：有 name_code 時查譯，缺則後端 name
//（技術識別字如 ENCRYPTION_KEY / JWT_SECRET 無 name_code，直接用後端 name）。
export function keyEnvName(row) {
  if (!row) return ''
  const code = row.name_code
  if (!code) return row.name || ''
  const key = `keyEnvName.${code}`
  const v = translated(key, () => t(key))
  if (v != null) return v
  warnMissingTranslation(key, code)
  return row.name || ''
}

// keyEnvNote env 金鑰說明：有 note_code 時查譯，缺則後端 note。
export function keyEnvNote(row) {
  if (!row) return ''
  const code = row.note_code
  if (!code) return row.note || ''
  const key = `keyEnvNote.${code}`
  const v = translated(key, () => t(key))
  if (v != null) return v
  warnMissingTranslation(key, code)
  return row.note || ''
}

// effectiveAccessNote 有效權限客體視角的角色隱含摘要（asset-multi-account
// UI 走查 F2）：後端 role_override_note 為 zh wire fallback、
// role_override_note_code 為機器碼；沿 keyEnvNote 同型查譯與降級。
export function effectiveAccessNote(resp) {
  if (!resp) return ''
  const code = resp.role_override_note_code
  if (!code) return resp.role_override_note || ''
  const key = `effectiveAccessNote.${code}`
  const v = translated(key, () => t(key))
  if (v != null) return v
  warnMissingTranslation(key, code)
  return resp.role_override_note || ''
}
