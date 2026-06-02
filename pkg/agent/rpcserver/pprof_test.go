package rpcserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPprofSwitch(t *testing.T) {
	pprofSwitch := NewPprofSwitch("127.0.0.1:21005")
	if pprofSwitch.URL() != "http://127.0.0.1:21005/debug/pprof/" {
		t.Fatalf("unexpected pprof url: %s", pprofSwitch.URL())
	}
	mux := http.NewServeMux()
	register := func(path string, handler http.Handler) error {
		mux.Handle(path, handler)
		return nil
	}
	if err := pprofSwitch.Install(register); err != nil {
		t.Fatalf("failed to install pprof handlers: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, PprofPath, nil)
	baseReq := httptest.NewRequest(http.MethodGet, PprofBasePath, nil)

	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected disabled pprof to return 404, got %d", resp.Code)
	}
	resp = httptest.NewRecorder()
	mux.ServeHTTP(resp, baseReq)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected disabled base pprof path to return 404, got %d", resp.Code)
	}

	pprofSwitch.Enable()
	resp = httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected enabled pprof to return 200, got %d", resp.Code)
	}
	resp = httptest.NewRecorder()
	mux.ServeHTTP(resp, baseReq)
	if resp.Code != http.StatusMovedPermanently {
		t.Fatalf("expected enabled base pprof path to redirect, got %d", resp.Code)
	}

	pprofSwitch.Disable()
	resp = httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected disabled pprof to return 404 after disable, got %d", resp.Code)
	}
}

func TestBuildPprofURL(t *testing.T) {
	tests := []struct {
		name        string
		metricsAddr string
		want        string
	}{
		{name: "empty", metricsAddr: "", want: PprofPath},
		{name: "disabled metrics", metricsAddr: "0", want: PprofPath},
		{name: "addr", metricsAddr: "127.0.0.1:21005", want: "http://127.0.0.1:21005/debug/pprof/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildPprofURL(tt.metricsAddr); got != tt.want {
				t.Fatalf("buildPprofURL(%q) = %q, want %q", tt.metricsAddr, got, tt.want)
			}
		})
	}
}
