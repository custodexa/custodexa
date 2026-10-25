import { t } from '@/i18n'
import { sourceFamiliesKey } from '@/utils/sourcePolicy'

// 兩個來源的家族欄**不同名**：`User` 物件是 `allowed_cidrs_families`
// （`model/user.go` 的 `AllowedCIDRFamilies`），判定端點回應是 `families`。
// 本函式只收陣列，呼叫端各自取對的欄位
export const effectiveUnrestrictedText = (families) => {
  const key = sourceFamiliesKey(families)
  return key ? t(`users.allowedCidrsEffective.${key}`) : ''
}
