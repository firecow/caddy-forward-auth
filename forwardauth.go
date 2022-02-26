package forwardauth

import (
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/go-resty/resty/v2"
	"net/http"
	"time"
)

func init() {
	caddy.RegisterModule(ForwardAuth{})
	httpcaddyfile.RegisterHandlerDirective("forward_auth", parseCaddyfile)
}

type ForwardAuth struct {
	Url                        string   `json:"url"`
	AuthResponseForwardHeaders []string `json:"auth_response_forward_headers"`

	restyClient *resty.Client
}

func (ForwardAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.forward_auth",
		New: func() caddy.Module { return new(ForwardAuth) },
	}
}

func (f *ForwardAuth) Provision(_ caddy.Context) error {
	f.restyClient = resty.New()
	f.restyClient.SetTimeout(5 * time.Second)
	f.restyClient.SetRedirectPolicy(resty.NoRedirectPolicy())

	return nil
}

func (f ForwardAuth) ServeHTTP(w http.ResponseWriter, clientReq *http.Request, next caddyhttp.Handler) error {

	authReqHeaders := map[string]string{}
	for k, v := range clientReq.Header {
		for _, v2 := range v {
			authReqHeaders[k] = v2
		}
	}
	derivedXForwardedHost := DeriveXForwardedHost(clientReq)
	derivedXForwardedFor := DeriveXForwardedFor(clientReq)
	authReqHeaders["x-forwarded-method"] = clientReq.Method
	authReqHeaders["x-forwarded-proto"] = clientReq.Proto
	authReqHeaders["x-forwarded-uri"] = clientReq.RequestURI
	authReqHeaders["x-forwarded-host"] = derivedXForwardedHost
	authReqHeaders["x-forwarded-for"] = derivedXForwardedFor
	delete(authReqHeaders, "host")
	authResp, err := f.restyClient.R().SetHeaders(authReqHeaders).Get(f.Url)
	if err != nil {
		return err
	}

	authRespStatusCode := authResp.StatusCode()
	if authRespStatusCode == 200 {
		for _, v := range f.AuthResponseForwardHeaders {
			authRespForwardHeader := authResp.Header().Get(v)
			if authRespForwardHeader != "" {
				clientReq.Header.Set(v, authRespForwardHeader)
			}
		}
		clientReq.Header.Set("x-forwarded-host", derivedXForwardedHost)
		return next.ServeHTTP(w, clientReq)
	}

	// if forward auth "fails" pass auth header and auth body to original response writer
	for k, v := range authResp.Header() {
		for _, v2 := range v {
			w.Header().Add(k, v2)
		}
	}
	w.WriteHeader(authRespStatusCode)
	_, err = w.Write(authResp.Body())
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
	var f ForwardAuth
	err := f.UnmarshalCaddyfile(h.Dispenser)

	if f.AuthResponseForwardHeaders == nil {
		// TODO: Make it possible to specify these via Caddyfile param
		f.AuthResponseForwardHeaders = append(f.AuthResponseForwardHeaders, "x-remote-user-uuid")
		f.AuthResponseForwardHeaders = append(f.AuthResponseForwardHeaders, "remote-user-uuid")
		f.AuthResponseForwardHeaders = append(f.AuthResponseForwardHeaders, "x-remote-user-id")
		f.AuthResponseForwardHeaders = append(f.AuthResponseForwardHeaders, "remote-user-id")
		f.AuthResponseForwardHeaders = append(f.AuthResponseForwardHeaders, "x-remote-user")
		f.AuthResponseForwardHeaders = append(f.AuthResponseForwardHeaders, "remote-user")
		f.AuthResponseForwardHeaders = append(f.AuthResponseForwardHeaders, "authorization")
	}

	return f, err
}

func (f *ForwardAuth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.Args(&f.Url) {
			return d.ArgErr()
		}
	}
	return nil
}

func DeriveXForwardedFor(clientReq *http.Request) string {
	var xForwardedFor string
	xForwardedFor = clientReq.Header.Get("cf-connecting-ip")
	if xForwardedFor == "" {
		xForwardedFor = clientReq.Header.Get("x-forwarded-for")
	}
	if xForwardedFor == "" {
		xForwardedFor = clientReq.RemoteAddr
	}
	return xForwardedFor
}

func DeriveXForwardedHost(clientReq *http.Request) string {
	var xForwardedHost string
	xForwardedHost = clientReq.Header.Get("x-forwarded-host")
	if xForwardedHost == "" {
		xForwardedHost = clientReq.Header.Get("host")
	}
	if xForwardedHost == "" {
		xForwardedHost = clientReq.Host
	}
	return xForwardedHost
}

// Interface guards
var (
	_ caddy.Validator             = (*ForwardAuth)(nil)
	_ caddyhttp.MiddlewareHandler = (*ForwardAuth)(nil)
	_ caddy.Provisioner           = (*ForwardAuth)(nil)
)
