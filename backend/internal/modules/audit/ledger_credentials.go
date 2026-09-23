package audit

import "strings"

// StripLedgerCredentials is a denylist, not the HTTP request-body allowlist.
// Tool arguments are evidence; only explicit credential fields are removed,
// including unexpected extra keys, before retention or encryption.
func StripLedgerCredentials(args map[string]any) map[string]any {
	var walk func(any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			out := make(map[string]any, len(x))
			for key, value := range x {
				switch strings.ToLower(key) {
				case "password", "passwd", "private_key", "private_key_passphrase", "passphrase", "token", "access_token", "refresh_token", "connect_token", "authorization", "api_key", "client_secret":
					continue
				}
				out[key] = walk(value)
			}
			return out
		case []any:
			out := make([]any, len(x))
			for i, value := range x {
				out[i] = walk(value)
			}
			return out
		default:
			return v
		}
	}
	return walk(args).(map[string]any)
}
