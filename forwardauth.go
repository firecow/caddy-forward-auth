package forwardauth

import (
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
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
}

func (ForwardAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.forward_auth",
		New: func() caddy.Module { return new(ForwardAuth) },
	}
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
	ssoReq.Header.Set("x-forwarded-uri", clientReq.URL.Path)
	ssoReq.Header.Del("host")

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
