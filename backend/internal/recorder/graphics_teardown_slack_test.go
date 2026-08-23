package recorder

import "testing"

// TestGraphicsTeardownSlackNotInflated 防放大守衛。
//
// 本測試守的不是「512 這個數字對不對」，而是「它不會被順手調大」。
//
// 圖形錄影的 DB 值與磁碟值必然有差額（guacd 持有 fd、收尾寫入發生在後端量測之後，
// 協議層無同步點），e2e 場景 16／17 因此以 `0 <= disk - db <= K` 的雙側界斷言取代
// 嚴格相等。K 一旦被調大，這條斷言就會從「抓得到截斷」退化成「抓不到東西」——
// 那正是本測試要防的失敗：
// **斷言放寬到抓不到東西，看起來修好了而實際沒有**。
//
// 調大前必須重新推導（見 `graphics_teardown_slack.go` 的推導：單則 dispose
// 上限 17 B、數量＝收線當下存活 layer/buffer 數且不隨會話成長、實測 RDP 3 則／VNC 1 則）
// **並一併改 spec 條文**（`openspec/specs/session-recording`）。
// e2e 偶爾紅**不是**調大 K 的理由：差額超過 K 表示收線落在畫格中途或收尾行為變了，
// 正解是查根因。
func TestGraphicsTeardownSlackNotInflated(t *testing.T) {
	const derivedUpperBound = 512

	if GraphicsTeardownSlackBytes > derivedUpperBound {
		t.Fatalf("GraphicsTeardownSlackBytes=%d 超過已推導的上界 %d bytes。"+
			"調大前請重新推導並同步 spec 條文；"+
			"不得以「e2e 偶爾紅」為由放寬——差額超界表示收線落在畫格中途或收尾行為變了。",
			GraphicsTeardownSlackBytes, derivedUpperBound)
	}

	// 下界同樣要守：調成 0 會讓斷言變成嚴格相等（本 change 已證明其必然偶爾紅），
	// 調成負數則無意義。
	if GraphicsTeardownSlackBytes <= 0 {
		t.Fatalf("GraphicsTeardownSlackBytes=%d 必須為正數——收尾差額必然存在，"+
			"歸零等於退回嚴格相等", GraphicsTeardownSlackBytes)
	}
}
