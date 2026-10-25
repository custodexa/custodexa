package asset

import "context"

type hostKeyClientIPKey struct{}

// ContextWithClientIP 把請求來源位址放進服務 ctx：連線測試的主機金鑰不符審計與告警據此記來源位址。
func ContextWithClientIP(ctx context.Context, ip string) context.Context {
	if ip == "" {
		return ctx
	}
	return context.WithValue(ctx, hostKeyClientIPKey{}, ip)
}

func clientIPFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	ip, _ := ctx.Value(hostKeyClientIPKey{}).(string)
	return ip
}
