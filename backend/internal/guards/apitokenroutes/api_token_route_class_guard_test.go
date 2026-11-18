package apitokenroutes

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/middleware"
)

// 守衛：路由登錄的三項分類。
//
//   - 每一列三項都是列舉內的值；開放的路由性質與對外連線都是已分類值（不是 unclassified）。
//   - 方法與性質不符的開放路由（性質為讀而方法不是 GET，或性質為寫而方法是 GET）與封閉清單雙向相同。
//   - 開放且請求處理中即對外連線（immediate）的路由與例外清單雙向相同。
//   - 兩份清單的每一條都附理由。
//
// 性質填錯的後果是唯讀的 token 可以寫入；新增或修改開放的路由時，這裡的失敗訊息就是審視的入口。

// routeClassSnapshot 登錄的全部列與兩份清單（守衛的輸入，測試可替換成合成資料）。
type routeClassSnapshot struct {
	entries   map[string]middleware.APITokenRouteClass
	mismatch  map[string]string
	immediate map[string]string
}

func currentRouteClassSnapshot(t *testing.T) routeClassSnapshot {
	t.Helper()
	snap := routeClassSnapshot{entries: map[string]middleware.APITokenRouteClass{},
		mismatch: middleware.APITokenMethodNatureMismatch(), immediate: middleware.APITokenImmediateOutboundExceptions()}
	for _, k := range middleware.APITokenRouteRegistryKeys() {
		c, ok := middleware.APITokenRouteClassOf(k)
		if !ok {
			t.Fatalf("登錄鍵 %q 查不到分類", k)
		}
		snap.entries[k] = c
	}
	if len(snap.entries) < routeGoldenLowerBound {
		t.Fatalf("登錄只有 %d 條（下界 %d）", len(snap.entries), routeGoldenLowerBound)
	}
	return snap
}

// methodNatureMismatched 開放路由的方法與性質是否不符。
func methodNatureMismatched(key string, c middleware.APITokenRouteClass) bool {
	method, _, _ := strings.Cut(key, " ")
	switch c.Nature {
	case middleware.RouteNatureRead:
		return method != http.MethodGet
	case middleware.RouteNatureWrite:
		return method == http.MethodGet
	}
	return false
}

// routeClassViolations 回傳全部違規（已排序）；空即通過。
func routeClassViolations(s routeClassSnapshot) []string {
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }
	for k, c := range s.entries {
		if !c.Known() {
			add("%s：分類有列舉外的值 %+v", k, c)
			continue
		}
		if c.Access != middleware.RouteAccessOpen {
			continue
		}
		if !c.Classified() {
			add("%s：開放的路由性質與對外連線都必須已分類，目前為 %s／%s", k, c.Nature, c.Outbound)
			continue
		}
		if methodNatureMismatched(k, c) {
			if _, listed := s.mismatch[k]; !listed {
				add("%s：方法與性質（%s）不符，須列入方法與性質不符清單並附理由", k, c.Nature)
			}
		}
		if c.Outbound == middleware.RouteOutboundImmediate {
			if _, listed := s.immediate[k]; !listed {
				add("%s：開放且立刻對外連線，須列入例外清單並附理由（否則不得開放）", k)
			}
		}
	}
	for k, reason := range s.mismatch {
		c, ok := s.entries[k]
		switch {
		case !ok:
			add("方法與性質不符清單的 %s 不在登錄內", k)
		case !c.Known() || c.Access != middleware.RouteAccessOpen || !c.Classified() || !methodNatureMismatched(k, c):
			add("方法與性質不符清單的 %s 不是方法與性質不符的開放路由（%+v）", k, c)
		}
		if strings.TrimSpace(reason) == "" {
			add("方法與性質不符清單的 %s 沒有理由", k)
		}
	}
	for k, reason := range s.immediate {
		c, ok := s.entries[k]
		switch {
		case !ok:
			add("立刻對外連線的例外 %s 不在登錄內", k)
		case !c.Known() || c.Access != middleware.RouteAccessOpen || c.Outbound != middleware.RouteOutboundImmediate || !c.Classified():
			add("立刻對外連線的例外 %s 不是開放且為 immediate 的路由（%+v）", k, c)
		}
		if strings.TrimSpace(reason) == "" {
			add("立刻對外連線的例外 %s 沒有理由", k)
		}
	}
	sort.Strings(out)
	return out
}

// TestAPITokenRouteClassesComplete 登錄的三項分類完整，兩份封閉清單與登錄一致。
func TestAPITokenRouteClassesComplete(t *testing.T) {
	snap := currentRouteClassSnapshot(t)
	if v := routeClassViolations(snap); len(v) > 0 {
		t.Fatalf("API token 路由登錄的分類有 %d 處違規：\n  %s", len(v), strings.Join(v, "\n  "))
	}
	open, read, write := 0, 0, 0
	for _, c := range snap.entries {
		if c.Access == middleware.RouteAccessOpen {
			open++
			switch c.Nature {
			case middleware.RouteNatureRead:
				read++
			case middleware.RouteNatureWrite:
				write++
			}
		}
	}
	if len(snap.mismatch) == 0 || len(snap.immediate) == 0 {
		t.Fatalf("兩份清單不應為空（不符 %d、例外 %d）：讀取退化時比對會假綠", len(snap.mismatch), len(snap.immediate))
	}
	t.Logf("登錄 %d 條、開放 %d（讀 %d、寫 %d）；方法與性質不符 %d 條、立刻對外連線例外 %d 條",
		len(snap.entries), open, read, write, len(snap.mismatch), len(snap.immediate))
}

// TestAPITokenRouteClassViolationsDetected 守衛本身能發現每一種違規（防止比對退化成恆真）。
func TestAPITokenRouteClassViolationsDetected(t *testing.T) {
	open := func(n middleware.APITokenRouteNature, o middleware.APITokenRouteOutbound) middleware.APITokenRouteClass {
		return middleware.APITokenRouteClass{Access: middleware.RouteAccessOpen, Nature: n, Outbound: o}
	}
	closed := middleware.APITokenRouteClass{Access: middleware.RouteAccessClosed, Nature: middleware.RouteNatureUnclassified, Outbound: middleware.RouteOutboundUnclassified}
	base := func() routeClassSnapshot {
		return routeClassSnapshot{
			entries: map[string]middleware.APITokenRouteClass{
				"GET /r":      open(middleware.RouteNatureRead, middleware.RouteOutboundNone),
				"POST /w":     open(middleware.RouteNatureWrite, middleware.RouteOutboundDeferred),
				"POST /pr":    open(middleware.RouteNatureRead, middleware.RouteOutboundNone),
				"GET /probe":  open(middleware.RouteNatureRead, middleware.RouteOutboundImmediate),
				"POST /c":     closed,
				"DELETE /c2":  closed,
				"GET /closed": {Access: middleware.RouteAccessClosed, Nature: middleware.RouteNatureRead, Outbound: middleware.RouteOutboundImmediate},
			},
			mismatch:  map[string]string{"POST /pr": "試算"},
			immediate: map[string]string{"GET /probe": "唯讀探測"},
		}
	}
	if v := routeClassViolations(base()); len(v) != 0 {
		t.Fatalf("合成的合法登錄不應有違規：%v", v)
	}
	cases := []struct {
		name   string
		mutate func(*routeClassSnapshot)
		want   string
	}{
		{"open with unclassified nature", func(s *routeClassSnapshot) {
			s.entries["POST /w"] = open(middleware.RouteNatureUnclassified, middleware.RouteOutboundNone)
		}, "POST /w：開放的路由性質與對外連線都必須已分類"},
		{"open with unclassified outbound", func(s *routeClassSnapshot) {
			s.entries["GET /r"] = open(middleware.RouteNatureRead, middleware.RouteOutboundUnclassified)
		}, "GET /r：開放的路由性質與對外連線都必須已分類"},
		{"empty nature", func(s *routeClassSnapshot) { s.entries["GET /r"] = open("", middleware.RouteOutboundNone) }, "GET /r：分類有列舉外的值"},
		{"typo outbound on closed route", func(s *routeClassSnapshot) {
			s.entries["POST /c"] = middleware.APITokenRouteClass{Access: middleware.RouteAccessClosed, Nature: middleware.RouteNatureUnclassified, Outbound: "later"}
		}, "POST /c：分類有列舉外的值"},
		{"unknown access", func(s *routeClassSnapshot) {
			s.entries["POST /c"] = middleware.APITokenRouteClass{Access: "maybe", Nature: middleware.RouteNatureWrite, Outbound: middleware.RouteOutboundNone}
		}, "POST /c：分類有列舉外的值"},
		{"mismatch list missing a row", func(s *routeClassSnapshot) { delete(s.mismatch, "POST /pr") }, "POST /pr：方法與性質（read）不符"},
		{"GET write not listed", func(s *routeClassSnapshot) {
			s.entries["GET /gw"] = open(middleware.RouteNatureWrite, middleware.RouteOutboundNone)
		}, "GET /gw：方法與性質（write）不符"},
		{"mismatch list extra row (consistent route)", func(s *routeClassSnapshot) { s.mismatch["GET /r"] = "多列" }, "方法與性質不符清單的 GET /r 不是方法與性質不符的開放路由"},
		{"mismatch list extra row (closed route)", func(s *routeClassSnapshot) { s.mismatch["POST /c"] = "多列" }, "方法與性質不符清單的 POST /c 不是方法與性質不符的開放路由"},
		{"mismatch list unregistered row", func(s *routeClassSnapshot) { s.mismatch["POST /gone"] = "多列" }, "方法與性質不符清單的 POST /gone 不在登錄內"},
		{"mismatch reason empty", func(s *routeClassSnapshot) { s.mismatch["POST /pr"] = " " }, "方法與性質不符清單的 POST /pr 沒有理由"},
		{"immediate list missing a row", func(s *routeClassSnapshot) { delete(s.immediate, "GET /probe") }, "GET /probe：開放且立刻對外連線"},
		{"immediate list extra row (not immediate)", func(s *routeClassSnapshot) { s.immediate["GET /r"] = "多列" }, "立刻對外連線的例外 GET /r 不是開放且為 immediate 的路由"},
		{"immediate list extra row (closed)", func(s *routeClassSnapshot) { s.immediate["GET /closed"] = "多列" }, "立刻對外連線的例外 GET /closed 不是開放且為 immediate 的路由"},
		{"immediate list unregistered row", func(s *routeClassSnapshot) { s.immediate["GET /gone"] = "多列" }, "立刻對外連線的例外 GET /gone 不在登錄內"},
		{"immediate reason empty", func(s *routeClassSnapshot) { s.immediate["GET /probe"] = "" }, "立刻對外連線的例外 GET /probe 沒有理由"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := base()
			c.mutate(&s)
			v := routeClassViolations(s)
			found := false
			for _, line := range v {
				if strings.Contains(line, c.want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("應發現「%s」，得到 %v", c.want, v)
			}
		})
	}
}
