package rpcserver

import (
	"fmt"
	"net/http"
	"net/http/pprof"
	"strings"
	"sync/atomic"
)

const (
	PprofBasePath = "/debug/pprof"
	PprofPath     = PprofBasePath + "/"
)

type PprofSwitch struct {
	enabled atomic.Bool
	url     string
}

func NewPprofSwitch(metricsAddr string) *PprofSwitch {
	return &PprofSwitch{
		url: buildPprofURL(metricsAddr),
	}
}

func (p *PprofSwitch) Enable() {
	p.enabled.Store(true)
}

func (p *PprofSwitch) Disable() {
	p.enabled.Store(false)
}

func (p *PprofSwitch) Enabled() bool {
	return p.enabled.Load()
}

func (p *PprofSwitch) URL() string {
	return p.url
}

func (p *PprofSwitch) Install(register func(string, http.Handler) error) error {
	handlers := []struct {
		path    string
		handler http.Handler
	}{
		{path: PprofBasePath, handler: p.baseHandler()},
		{path: PprofPath, handler: p.handler(pprof.Index)},
		{path: PprofPath + "cmdline", handler: p.handler(pprof.Cmdline)},
		{path: PprofPath + "profile", handler: p.handler(pprof.Profile)},
		{path: PprofPath + "symbol", handler: p.handler(pprof.Symbol)},
		{path: PprofPath + "trace", handler: p.handler(pprof.Trace)},
	}

	for _, item := range handlers {
		if err := register(item.path, item.handler); err != nil {
			return err
		}
	}
	return nil
}

func (p *PprofSwitch) handler(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !p.Enabled() {
			http.NotFound(w, r)
			return
		}
		next(w, r)
	})
}

func (p *PprofSwitch) baseHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !p.Enabled() {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, PprofPath, http.StatusMovedPermanently)
	})
}

func buildPprofURL(metricsAddr string) string {
	metricsAddr = strings.TrimSpace(metricsAddr)
	if metricsAddr == "" || metricsAddr == "0" {
		return PprofPath
	}
	return fmt.Sprintf("http://%s%s", metricsAddr, PprofPath)
}
