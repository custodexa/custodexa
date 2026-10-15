// 瀏覽器儲存讀寫一律容錯：私密視窗或封鎖站台資料時只失去記憶，不影響操作
export function readStorage(key) {
  try {
    return localStorage.getItem(key)
  } catch {
    return null
  }
}

export function writeStorage(key, value) {
  try {
    localStorage.setItem(key, value)
  } catch { /* 寫不進去：本次操作照常，下次回到預設 */ }
}
