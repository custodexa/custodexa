package model

import (
	"strings"
	"testing"
)

func TestAgentToolCallBounds(t *testing.T) {
	base := AgentToolCall{Seq: 1, UserID: 1, AgentTokenID: 1, OwnerUserID: 1, Tool: "list_assets", ArgsRedacted: "{}", Decision: ToolCallPending}
	for _, tool := range []string{"list_assets", "request_access", "check_request"} {
		a := base
		a.Tool = tool
		if err := a.Validate(); err != nil {
			t.Fatal(tool, err)
		}
	}
	a := base
	a.Tool = "run_command"
	if a.Validate() == nil {
		t.Fatal("missing task accepted")
	}
	id := uint(4)
	a.AccessRequestID = &id
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	a.ResultExcerpt = strings.Repeat("x", 2048)
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	a.ResultExcerpt += "x"
	if a.Validate() == nil {
		t.Fatal("oversized excerpt accepted")
	}
	a.ResultExcerpt = strings.Repeat("界", 683)
	if a.Validate() == nil {
		t.Fatal("UTF-8 byte bound not enforced")
	}
}
