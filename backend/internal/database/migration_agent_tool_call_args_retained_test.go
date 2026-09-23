package database

import (
	"github.com/custodexa/backend/internal/testgate"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestMigrationAgentToolCallArgsRegistered(t *testing.T) {
	found := false
	for _, m := range migrations {
		if m.Version == "20260924_agent_tool_call_args_retained" {
			found = true
			require.NotNil(t, m.Up)
			require.NotNil(t, m.Down)
		}
	}
	require.True(t, found)
}
func TestMigrationAgentToolCallArgsPostgres(t *testing.T) {
	db := freshSchema(t, testgate.Value(t, testgate.EnvPGDSN), "tool_args_retained_test")
	// A pre-change row must keep its original HMAC and be explicitly unretained.
	require.NoError(t, db.Exec(`CREATE TABLE agent_tool_calls (id bigserial PRIMARY KEY, integrity_hmac text NOT NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO agent_tool_calls (integrity_hmac) VALUES ('existing-hmac')`).Error)
	require.NoError(t, applyAgentToolCallArgsRetained(db))
	var row struct {
		ArgsSealed    []byte
		ArgsRetained  bool
		IntegrityHMAC string
	}
	require.NoError(t, db.Table("agent_tool_calls").First(&row).Error)
	require.False(t, row.ArgsRetained)
	require.Nil(t, row.ArgsSealed)
	require.Equal(t, "existing-hmac", row.IntegrityHMAC)
	shape := columnShapes(t, db, "tool_args_retained_test")
	require.Equal(t, "bytea", shape["agent_tool_calls.args_sealed"].DataType)
	require.Equal(t, "YES", shape["agent_tool_calls.args_sealed"].Nullable)
	require.Equal(t, "boolean", shape["agent_tool_calls.args_retained"].DataType)
	require.Equal(t, "NO", shape["agent_tool_calls.args_retained"].Nullable)
	require.Equal(t, "false", shape["agent_tool_calls.args_retained"].Default)
	require.NoError(t, rollbackAgentToolCallArgsRetained(db))
	require.True(t, db.Migrator().HasColumn("agent_tool_calls", "args_sealed"))
}
