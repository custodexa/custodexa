// 鑰匙狀態與彩標的單一來源。抽屜與熔斷處置頁原本各寫一份映射，同一把停用的
// 鑰匙在抽屜是琥珀、在熔斷頁是中性——讀者在兩頁之間看到兩種嚴重度。
//
// 語意固定：琥珀＝現在還有事要處置（熔斷待處置期間的停用鑰匙）；
// 熔斷解除後，停用是無法復原的終局狀態（只能另發一把），改中性。
export const AGENT_TOKEN_STATES = ['valid', 'suspended', 'revoked', 'expired']

export function agentTokenState(token, now = Date.now()) {
  if (!token) return 'valid'
  if (token.revoked_at) return 'revoked'
  if (token.suspended_at) return 'suspended'
  return token.expires_at && Date.parse(token.expires_at) <= now ? 'expired' : 'valid'
}

export function agentTokenTagType(state, breakerPending = false) {
  if (state === 'valid') return 'success'
  if (state === 'suspended') return breakerPending ? 'warning' : 'info'
  return 'info'
}

// 終局狀態（撤銷、到期、熔斷已解除後的停用）沒有待辦，也不該佔用品牌青：
// el-tag 的 info 在本主題映到 --ot-info（品牌青），與身分徽章同色。
// 這些格改掛中性彩標類別。
export function agentTokenTagClass(state, breakerPending = false) {
  return agentTokenTagType(state, breakerPending) === 'info' ? 'ot-tag-neutral' : ''
}
