import { ref } from 'vue'

/**
 * 詳情頁標題要帶資料（例如任務主旨），但麵包屑在版面層算，拿不到那份資料。
 * 由詳情頁載入後寫入、離開時清掉；版面層只讀，讀不到就退回不帶主旨的標題。
 */
export const detailSubject = ref('')

/** 標題裡的主旨只取前 24 字：再長就會把麵包屑撐過一行 */
export function briefSubject(text, max = 24) {
  const value = String(text || '').trim()
  if (!value) return ''
  return value.length > max ? `${value.slice(0, max)}…` : value
}

export function setDetailSubject(text) {
  detailSubject.value = briefSubject(text)
}

export function clearDetailSubject() {
  detailSubject.value = ''
}
