package kernel

import "testing"

// TestDedupeUintKeepsFirstOccurrenceOrder 去重須保序且只留首次出現。
//
// 保序是契約：呼叫端把結果餵給 `WHERE id IN ?` 與長度比對（成員名單完整性判定），
// 順序抖動會讓稽核 diff 與測試產生假訊號。
func TestDedupeUintKeepsFirstOccurrenceOrder(t *testing.T) {
	cases := []struct {
		name string
		in   []uint
		want []uint
	}{
		{"nil 回空切片而非 nil", nil, []uint{}},
		{"空切片", []uint{}, []uint{}},
		{"無重複時原樣保序", []uint{3, 1, 2}, []uint{3, 1, 2}},
		{"重複只留首次", []uint{3, 1, 3, 2, 1}, []uint{3, 1, 2}},
		{"全同", []uint{7, 7, 7}, []uint{7}},
		{"零值不被當成空位", []uint{0, 0, 5}, []uint{0, 5}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DedupeUint(c.in)
			if got == nil {
				t.Fatal("回傳 nil：呼叫端以 len() 比對成員數，nil 與空切片的差異會在 JSON 序列化端外顯")
			}
			if len(got) != len(c.want) {
				t.Fatalf("DedupeUint(%v) = %v，長度 %d，want %v", c.in, got, len(got), c.want)
			}
			for i := range c.want {
				if got[i] != c.want[i] {
					t.Fatalf("DedupeUint(%v) = %v, want %v", c.in, got, c.want)
				}
			}
		})
	}
}

// TestDedupeUintDoesNotMutateInput 輸入切片不得被就地改寫（呼叫端常在去重後仍用原切片）。
func TestDedupeUintDoesNotMutateInput(t *testing.T) {
	in := []uint{2, 1, 2, 3}
	_ = DedupeUint(in)
	want := []uint{2, 1, 2, 3}
	for i := range want {
		if in[i] != want[i] {
			t.Fatalf("輸入被改寫：%v，want %v", in, want)
		}
	}
}
