package forwardauth

import (
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"io"
	"net/http"
)

func init() {
	caddy.RegisterModule(ForwardAuth{})
	httpcaddyfile.RegisterHandlerDirective("forwardAuth", parseCaddyfile)
}

type ForwardAuth struct {
	ForwardAuthUrl string `json:"forwardAuthUrl"`
}

func (ForwardAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.http.handlers.forwardauth",
		New: func() caddy.Module { return new(ForwardAuth) },
	}
}

func (f ForwardAuth) ServeHTTP(w http.ResponseWriter, clientReq *http.Request, next caddyhttp.Handler) error {

	client := http.Client{}

	ssoReq, err := http.NewRequest("GET", f.ForwardAuthUrl, nil)
	if err != nil {
		return err
	}
	headerClone := clientReq.Header.Clone()
	clientReq.Header.Del("host")

	ssoReq.Header = headerClone

	ssoRes, err := client.Do(ssoReq)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(ssoRes.Body)

	if ssoRes.StatusCode == 200 {
		return next.ServeHTTP(w, clientReq)
	}

	w.WriteHeader(ssoRes.StatusCode)
	err = ssoRes.Header.Write(w)
	if err != nil {
		return err
	}

	_, err = io.Copy(w, ssoRes.Body)
	if err != nil {
		return err
	}

	return nil
}

func (f *ForwardAuth) Provision(ctx caddy.Context) error {
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
	_ caddy.Provisioner           = (*ForwardAuth)(nil)
	_ caddy.Validator             = (*ForwardAuth)(nil)
	_ caddyhttp.MiddlewareHandler = (*ForwardAuth)(nil)
	_ caddyfile.Unmarshaler       = (*ForwardAuth)(nil)
)
