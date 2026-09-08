package model

import (
	"math"
	"strconv"
	"testing"
)

func TestRoleMappingChannelRoundTrip(t *testing.T) {
	for _, kind := range []string{RoleMappingChannelKindDirectory, RoleMappingChannelKindProvider} {
		channel := RoleMappingChannel(kind, 42)
		gotKind, gotID, err := ParseRoleMappingChannel(channel)
		if err != nil {
			t.Fatalf("%s: 解析失敗: %v", channel, err)
		}
		if gotKind != kind || gotID != 42 {
			t.Fatalf("%s: 得到 %s/%d", channel, gotKind, gotID)
		}
	}
}

func TestParseRoleMappingChannelRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"未知種類":    "ldap:1",
		"缺分隔符":    "provider1",
		"非數字":     RoleMappingChannelKindProvider + ":x",
		"超出 uint": RoleMappingChannelKindProvider + ":" + strconv.FormatUint(math.MaxUint64, 10) + "0",
	}
	for name, channel := range cases {
		if _, _, err := ParseRoleMappingChannel(channel); err == nil {
			t.Errorf("%s（%q）應解析失敗", name, channel)
		}
	}
}

// 來源識別的上限必須跟著 uint 的平台字長走，不能依賴 64 位元解析後再轉型。
func TestParseRoleMappingChannelBoundedByPlatformUint(t *testing.T) {
	max := uint64(math.MaxUint)
	channel := RoleMappingChannelKindProvider + ":" + strconv.FormatUint(max, 10)
	if _, id, err := ParseRoleMappingChannel(channel); err != nil || uint64(id) != max {
		t.Fatalf("上限值應可解析: id=%d err=%v", id, err)
	}
	over := RoleMappingChannelKindProvider + ":" + strconv.FormatUint(max, 10) + "0"
	if _, _, err := ParseRoleMappingChannel(over); err == nil {
		t.Fatalf("超過 uint 上限應報錯: %q", over)
	}
}
