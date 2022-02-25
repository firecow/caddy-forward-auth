package forwardauth

import (
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"io"
	"net/http"
	"time"
)

func init() {
	caddy.RegisterModule(ForwardAuth{})
	httpcaddyfile.RegisterHandlerDirective("forward_auth", parseCaddyfile)
}

type ForwardAuth struct {
	Url string `json:"url"`

	logger *zap.Logger
}

func (ForwardAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.forward_auth",
		New: func() caddy.Module { return new(ForwardAuth) },
	}
}

// Provision sets up RequestDebugger.
func (f *ForwardAuth) Provision(ctx caddy.Context) error {
	f.logger = ctx.Logger(f)
	return nil
}

func (f ForwardAuth) ServeHTTP(w http.ResponseWriter, clientReq *http.Request, next caddyhttp.Handler) error {

	client := http.Client{Timeout: 5 * time.Second}

	ssoReq, err := http.NewRequest("GET", f.Url, nil)
	if err != nil {
		return err
	}

	ssoReq.Header = clientReq.Header.Clone()
	ssoReq.Header.Set("x-forwarded-method", clientReq.Method)
	ssoReq.Header.Set("x-forwarded-proto", clientReq.Proto)
	ssoReq.Header.Set("x-forwarded-host", clientReq.Host)
	ssoReq.Header.Set("x-forwarded-uri", clientReq.RequestURI)
	ssoReq.Header.Del("host")

	f.logger.Info("ssoReq.Header",
		zap.Any("ssoReq.x-forwarded-method", ssoReq.Header.Get("x-forwarded-method")),
		zap.Any("ssoReq.x-forwarded-proto", ssoReq.Header.Get("x-forwarded-proto")),
		zap.Any("ssoReq.x-forwarded-host", ssoReq.Header.Get("x-forwarded-host")),
		zap.Any("ssoReq.x-forwarded-uri", ssoReq.Header.Get("x-forwarded-uri")),
	)

	ssoW, err := client.Do(ssoReq)
	if err != nil {
		return err
	}
	defer ssoW.Body.Close()

	if ssoW.StatusCode == 200 {
		return next.ServeHTTP(w, clientReq)
	}

	for k, v := range ssoW.Header {
		for _, v2 := range v {
			w.Header().Add(k, v2)
		}
	}
	clientReq.Header.Set("x-forwarded-host", clientReq.Header.Get("host"))
	w.WriteHeader(ssoW.StatusCode)

	_, err = io.Copy(w, ssoW.Body)
	if err != nil {
		return err
	}

	return nil
}

func (f *ForwardAuth) Validate() error {
	if f.Url == "" {
		return fmt.Errorf("forward_auth <url> not specified")
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m ForwardAuth
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

func (f *ForwardAuth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.Args(&f.Url) {
			return d.ArgErr()
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Validator             = (*ForwardAuth)(nil)
	_ caddyhttp.MiddlewareHandler = (*ForwardAuth)(nil)
)
