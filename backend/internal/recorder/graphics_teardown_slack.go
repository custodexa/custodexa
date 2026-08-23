package recorder

// GraphicsTeardownSlackBytes 圖形錄影「磁碟實際大小 − 持久化大小」的容許上界（bytes）。
//
// 這是 e2e 場景 16／17 錄影大小斷言的**單一定義點**：`scripts/e2e_smoke.sh` 以 grep
// 從本檔取值，不在腳本內另寫死。改動本常數前必讀下方推導。
//
// # 為什麼會有差額
//
// 圖形錄影（`.guac`）的檔案描述子由 guacd 持有，不是後端。後端在隧道返回後 `os.Stat`
// 取大小（`internal/proxy/handler.go` 的錄影落地段），而 guacd 之後還會寫入收尾尾段：
// 釋放顯示層時對每個 `layer->index != 0` 的 layer 各送一則 dispose 指令
// （`libguac/display-layer-list.c:368-379` 的 `guac_display_free_removed_layers`）。
// 協議層不提供收尾完成訊號，guacd 亦不會先行關閉與後端之間的 TCP（它等後端先關），
// 故後端不存在可用的同步點——差額無法消除，只能界定。方向恆為**少記**（DB ≤ 磁碟）。
//
// # 單則 dispose 的位元組數（上限 17 B）
//
// Guacamole 指令編碼為 `<len>.<value>` 逗號分隔、分號結尾：
//
//	7.dispose,2.-6;   →  `7.dispose,` 10 B ＋ `2.-6` 4 B ＋ `;` 1 B = 15 B
//
// `7.dispose,` 固定 10 B；index 部分為 `<位數>.<index>`，index 字串 1–4 字元對應 3–6 B；
// 結尾分號 1 B。故單則上限 = 10 + 6 + 1 = 17 B。
//
// # 為什麼數量不隨會話成長
//
// 數量等於**收線當下仍存活的 layer/buffer 數**，不是畫面複雜度、不是會話長度：
// 會話進行中被釋放的 layer 在下一次 frame flush 就已寫掉 dispose
// （`rdp/pointer.c:110-115` `guac_rdp_pointer_free` → `guac_display_free_layer` →
// `guac_display_remove_layer`），不累積到收尾；RDP 每個滑鼠游標形狀配一個 buffer
// （`rdp/pointer.c:40`），收尾時仍在 FreeRDP pointer cache 內的才計入，其容量是與會話
// 長度無關的固定級距。實測 RDP 3 則（45 B）、VNC 1 則（15 B）。
//
// # 為什麼取 512
//
// 512 B ≈ 30 則 17 B 的 dispose，比實測（1–3 則）高一個數量級，並涵蓋 pointer cache
// 級距。取 2 的冪只為可讀，無其他含義。
//
// # 適用前提（K 不是普遍上界）
//
// 上述推導成立於「**收線時 guacd 不在畫格中途**」。guacd 的錄影 socket 是 socket-fd，
// 帶 `GUAC_SOCKET_OUTPUT_BUFFER_SIZE = 8192` 的輸出緩衝
// （`libguac/guacamole/socket-constants.h:32`），tee socket 的 flush 同時 flush 錄影側
// （`socket-tee.c:114-122`）；緩衝在畫格邊界被清空，故靜態桌面下收尾殘量就只有 dispose。
// 但若收線恰好落在畫面高速更新的畫格中途，`guac_client_free` 之前仍在跑的渲染執行緒會
// 把該畫格寫完，殘量可達**一個畫格的量級（遠大於 512 B）**。
//
// 因此本常數只對 **e2e 場景 16／17** 這種靜態畫面靶機（`rdp-test` / `vnc-test`，
// `backend/scripts/guacws_smoke.go` 只做建線與 sync 幀計數，不產生畫面活動）成立。
// spec 層的不變式是方向式的（`db <= disk` 且 `db > 0`、差額限於收尾尾段且不隨會話成長），
// **不寫死位元組數**——寫死會讓一個只在特定場景成立的數字變成普遍承諾。
//
// # 不得為了讓 e2e 變綠而調大
//
// 差額超過本上界表示收線落在畫格中途、或收尾行為變了，正解是查為什麼，不是把界線推開。
// 調大前必須重新推導（見上方推導）並一併改 spec 條文；
// `TestGraphicsTeardownSlackNotInflated` 會在調大時打紅，強迫改動者面對本註解。
const GraphicsTeardownSlackBytes = 512
