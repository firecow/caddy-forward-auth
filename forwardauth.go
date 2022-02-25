package forwardauth

import (
	"bytes"
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/go-resty/resty/v2"
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
	authReq := resty.New()
	authReq.SetTimeout(5 * time.Second)
	authReq.SetRedirectPolicy(resty.NoRedirectPolicy())
	authReqHeaders := map[string]string{}
	for k, v := range clientReq.Header {
		for _, v2 := range v {
			authReqHeaders[k] = v2
		}
	}
	authReqHeaders["x-forwarded-method"] = clientReq.Method
	authReqHeaders["x-forwarded-proto"] = clientReq.Proto
	authReqHeaders["x-forwarded-uri"] = clientReq.RequestURI
	authReqHeaders["x-forwarded-host"] = clientReq.Header.Get("x-forwarded-host")
	if authReqHeaders["x-forwarded-host"] == "" {
		authReqHeaders["x-forwarded-host"] = clientReq.Header.Get("host")
	}
	if authReqHeaders["x-forwarded-host"] == "" {
		authReqHeaders["x-forwarded-host"] = clientReq.Host
	}
	delete(authReqHeaders, "host")
	authResp, err := authReq.R().SetHeaders(authReqHeaders).Get(f.Url)
	if err != nil {
		return err
	}

	authRespStatusCode := authResp.StatusCode()
	if authRespStatusCode == 200 {
		clientReq.Header.Set("x-forwarded-host", authReqHeaders["x-forwarded-host"])
		return next.ServeHTTP(w, clientReq)
	}

	// if forward auth "fails" pass auth header and auth body to original response writer
	for k, v := range authResp.Header() {
		for _, v2 := range v {
			w.Header().Add(k, v2)
		}
	}
	w.WriteHeader(authRespStatusCode)
	_, err = io.Copy(w, bytes.NewReader(authResp.Body()))
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
