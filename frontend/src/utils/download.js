// 二進位回應 → 觸發瀏覽器另存。
//
// 匯出類端點回的是檔案本體（blob）而非 JSON，瀏覽器沒有內建的「存這個回應」
// 入口，只能自造一個帶 download 屬性的連結按下去再收掉。此模式原本散在
// AuditLogs／KeyManagement／TransmissionInventory 等頁各寫一份，抽出來供
// 新的呼叫端複用（既有頁面維持原狀，本 change 不做無關重構）。
//
// revokeObjectURL 一定要呼叫：不收回的 object URL 會把整個 blob 釘在記憶體裡
// 直到分頁關閉，匯出包動輒數十 MB。
export function downloadBlob(blob, filename) {
  const url = window.URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  window.URL.revokeObjectURL(url)
}

// timestampSuffix 檔名用時間戳（YYYYMMDD-HHmmss，本地時區）。
// 同一個範圍匯出兩次要能在下載目錄裡分辨先後
export function timestampSuffix(date = new Date()) {
  const p = (n) => String(n).padStart(2, '0')
  return (
    `${date.getFullYear()}${p(date.getMonth() + 1)}${p(date.getDate())}` +
    `-${p(date.getHours())}${p(date.getMinutes())}${p(date.getSeconds())}`
  )
}
