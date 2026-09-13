package vaulttransit

import (
	"context"
	"net/http"
)

// WizardHTTPClient is test source only. The server integration test exposes it
// to its child through a temporary go-test overlay, never a production build.
// It uses the same private HTTP seam as the real AppRole integration tests.
func WizardHTTPClient(ctx context.Context, s Settings, address string, status func(string, int)) (*Client, error) {
	wire, err := checkedAdapter(address, &http.Transport{}, true)
	if err != nil {
		return nil, err
	}
	wire.http.Transport = &wizardHTTPTrace{base: wire.http.Transport, status: status}
	return startClient(ctx, s, wire, wallClock{})
}

type wizardHTTPTrace struct {
	base   http.RoundTripper
	status func(string, int)
}

func (w *wizardHTTPTrace) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := w.base.RoundTrip(r)
	if err == nil {
		w.status(r.Method+" "+r.URL.Path, resp.StatusCode)
	}
	return resp, err
}

func (w *wizardHTTPTrace) CloseIdleConnections() {
	w.base.(interface{ CloseIdleConnections() }).CloseIdleConnections()
}
