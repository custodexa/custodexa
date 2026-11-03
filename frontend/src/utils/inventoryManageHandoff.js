// 主機帳號盤點「納管」的跨頁預填暫存。
//
// 只活在前端記憶體的模組層單一變數：不進網址、不進 history.state、不進 localStorage。
// 取出即清空；資產識別與要開的資產不同時丟棄。重新整理會重建記憶體，暫存自然消失。

let pending = null

/** @param {{assetId: number|string, username: string, privileged: boolean}} prefill */
export function stashManagePrefill(prefill) {
  pending = prefill
    ? { assetId: Number(prefill.assetId), username: String(prefill.username ?? ''), privileged: !!prefill.privileged }
    : null
}

/**
 * 取出並清空暫存。
 * @param {number|string} assetId 現在要開編輯抽屜的資產
 * @returns {{assetId: number, username: string, privileged: boolean}|null}
 */
export function takeManagePrefill(assetId) {
  const got = pending
  pending = null
  if (!got || got.assetId !== Number(assetId)) return null
  return got
}

/** 只供測試：暫存目前是否為空 */
export function hasManagePrefill() {
  return pending !== null
}
