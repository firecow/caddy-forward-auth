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
	ForwardAuthUrl string `json:"forwardAuthUrl"`
}

func (ForwardAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.forward_auth",
		New: func() caddy.Module { return new(ForwardAuth) },
	}
}

func (f ForwardAuth) ServeHTTP(w http.ResponseWriter, clientReq *http.Request, next caddyhttp.Handler) error {

	client := http.Client{Timeout: 5 * time.Second}

	ssoReq, err := http.NewRequest("GET", f.ForwardAuthUrl, nil)
	if err != nil {
		return err
	}
	headerClone := clientReq.Header.Clone()
	clientReq.Header.Del("host")

	ssoReq.Header = headerClone

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
	w.WriteHeader(ssoW.StatusCode)

	_, err = io.Copy(w, ssoW.Body)
	if err != nil {
		return err
	}

	return nil
}

func (f *ForwardAuth) Validate() error {
	if f.ForwardAuthUrl == "" {
		return fmt.Errorf("no forward auth url specified")
	}
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m ForwardAuth
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

func (f *ForwardAuth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.Args(&f.ForwardAuthUrl) {
			return d.ArgErr()
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Validator             = (*ForwardAuth)(nil)
	_ caddyhttp.MiddlewareHandler = (*ForwardAuth)(nil)
	_ caddyfile.Unmarshaler       = (*ForwardAuth)(nil)
)
