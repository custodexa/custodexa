// 目錄測試連線的本頁結果，給接通前確認面板用（結果綁定送出當下的表單）。
//
// 每次送出記下表單快照與遞增序號；回覆不是最新一次送出的就丟棄。
// 過期（表單已改）與尚未儲存（受測快照≠已儲存）的判定在 preflightLights.js。
// 快照不含密碼欄：儲存後輸入框會清空，把它算進來會讓剛存好的設定被誤判為已過期。
import { ref, computed } from 'vue'

const SECRET_FIELDS = ['bind_password', 'clear_bind_password']

export const ldapComparable = (form) => {
  const copy = { ...form }
  for (const k of SECRET_FIELDS) delete copy[k]
  return JSON.stringify(copy)
}

/**
 * @param {object} form 表單（reactive）
 * @param {() => string} savedSnapshot 已儲存設定的快照（以 ldapComparable 算）
 */
export function useLdapTestRecord(form, savedSnapshot) {
  const record = ref(null)
  let seq = 0

  /** 送出前呼叫，回傳這次的票 */
  const begin = () => ({ seq: ++seq, snapshot: ldapComparable(form), attr: form.attr_group || '' })

  /** 回覆到達時呼叫：不是最新一次送出的回 false（呼叫端丟棄） */
  const accept = (ticket, result) => {
    if (ticket.seq !== seq) return false
    record.value = result
      ? { result, at: new Date().toISOString(), snapshot: ticket.snapshot, attr: ticket.attr }
      : null
    return true
  }

  const panelInput = computed(() => ({
    record: record.value,
    current: ldapComparable(form),
    saved: savedSnapshot(),
  }))

  return { record, begin, accept, panelInput }
}
