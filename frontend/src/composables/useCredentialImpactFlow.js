import { ref } from 'vue'
import { confirmCredentialImpact } from '@/api/credentials'

/**
 * 共用憑證修改的範圍外影響確認流程（更正登記值與改密共用）。
 *
 * 送出前先向確認端點問一次：
 *   - `required: false`：直接送出，請求不帶確認欄；
 *   - `required: true`：開確認對話框，使用者勾選知情後，才以 `impact_confirmation_id` 送出。
 * 提交時若範圍外集合在這段期間擴大，伺服器回 409
 * （RULE_CREDENTIAL_IMPACT_CONFIRMATION_REQUIRED）；此時重取確認並以新的台數重開對話框，
 * 呼叫端已輸入的明文原封不動（本流程不碰輸入）。範圍外台數與清單一律取自伺服器回應，
 * 前端不自行計算範圍。
 */

export const IMPACT_CONFLICT_CODE = 'RULE_CREDENTIAL_IMPACT_CONFIRMATION_REQUIRED'

/** 該錯誤是否為「需要影響確認」的 409。 */
export function isImpactConflict(err) {
  return err?.response?.status === 409 && err?.response?.data?.code === IMPACT_CONFLICT_CODE
}

/** 供 `skipErrorToast` 使用：影響確認的 409 由本流程處理，不另跳全域錯誤提示。 */
export const skipImpactConflictToast = (err) => isImpactConflict(err)

async function fetchImpact(credentialId, operation) {
  const res = await confirmCredentialImpact(credentialId, operation)
  return {
    required: !!res?.required,
    confirmationId: res?.confirmation_id || '',
    inScopeCount: Number.isInteger(res?.in_scope_count) ? res.in_scope_count : 0,
    outOfScopeCount: Number.isInteger(res?.out_of_scope_asset_count) ? res.out_of_scope_asset_count : 0,
  }
}

/**
 * @param {() => number|string} getCredentialId - 取得目前憑證識別
 * @param {'set_secret'|'rotate'} operation
 */
export function useCredentialImpactFlow(getCredentialId, operation) {
  const visible = ref(false)
  const impact = ref(null)
  const working = ref(false)
  // 每次（重）開對話框遞增：對話框據此清掉上一輪的勾選
  const epoch = ref(0)
  let pendingSend = null

  function open(info, send) {
    pendingSend = send
    impact.value = info
    epoch.value += 1
    visible.value = true
  }

  function reset() {
    visible.value = false
    impact.value = null
    pendingSend = null
  }

  /**
   * 開始一次送出。`send(extra)` 執行真正的提交，`extra` 為空物件或 `{ impact_confirmation_id }`。
   * 回傳 true＝已送出；false＝等待使用者在對話框確認。提交本身的錯誤原樣往外丟。
   */
  async function start(send) {
    working.value = true
    try {
      const info = await fetchImpact(getCredentialId(), operation)
      if (!info.required) {
        try {
          await send({})
          return true
        } catch (err) {
          // 取得確認後、提交前範圍外集合才出現：同樣走確認流程，不把 409 吞掉
          if (!isImpactConflict(err)) throw err
          const again = await fetchImpact(getCredentialId(), operation)
          if (!again.required) throw err
          open(again, send)
          return false
        }
      }
      open(info, send)
      return false
    } finally {
      working.value = false
    }
  }

  /**
   * 先送出、被要求確認才補確認：用於「儲存本身不需要輪替能力」的流程，
   * 避免為了問影響而擋住原本可存的修改。回傳值同 `start`。
   * 收到影響確認 409 後重查：仍需確認就開對話框；已不需確認就原樣重送一次，
   * 重送的錯誤（含再次 409）原樣往外丟，由呼叫端提示。
   */
  async function startSendFirst(send) {
    working.value = true
    try {
      try {
        await send({})
        return true
      } catch (err) {
        if (!isImpactConflict(err)) throw err
      }
      const info = await fetchImpact(getCredentialId(), operation)
      if (!info.required) {
        await send({})
        return true
      }
      open(info, send)
      return false
    } finally {
      working.value = false
    }
  }

  /** 使用者勾選並按下確認。回傳 true＝已送出完成；false＝以新台數重開了對話框。 */
  async function confirm() {
    if (!pendingSend || !impact.value) return false
    const send = pendingSend
    working.value = true
    try {
      await send({ impact_confirmation_id: impact.value.confirmationId })
      reset()
      return true
    } catch (err) {
      if (!isImpactConflict(err)) throw err
      const info = await fetchImpact(getCredentialId(), operation)
      if (!info.required) {
        await send({})
        reset()
        return true
      }
      open(info, send)
      return false
    } finally {
      working.value = false
    }
  }

  function cancel() {
    reset()
  }

  return { visible, impact, working, epoch, start, startSendFirst, confirm, cancel }
}
