package forwardauth

import (
	"fmt"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/go-resty/resty/v2"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestForwardAuth200(t *testing.T) {

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log(r.Header.Get("x-forwarded-for"))

		w.Header().Set("remote-user", "mynameisslimshady")
		w.WriteHeader(200)
	}))
	defer s.Close()

	f := ForwardAuth{
		Url:                        s.URL,
		AuthResponseForwardHeaders: []string{"remote-user"},
		restyClient:                resty.New(),
	}

	nextCalled := false
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://localhost/somepath", nil)
	err := f.ServeHTTP(w, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		nextCalled = true
		return nil
	}))
	assert.Nil(t, err)

	assert.Equal(t, "localhost", req.Header.Get("x-forwarded-host"))
	assert.Equal(t, "mynameisslimshady", req.Header.Get("remote-user"))
	assert.Equal(t, true, nextCalled, "Next was not called")
}

func TestForwardAuthNot200WithHostHeader(t *testing.T) {
	ForwardAuthNot200WithHostHeader(t, "somewhereovertherainbox.com", "somewhereovertherainbox.com")
}

func TestForwardAuthNot200WithoutHostHeader(t *testing.T) {
	ForwardAuthNot200WithHostHeader(t, "", "localhost")
}

func ForwardAuthNot200WithHostHeader(t *testing.T, hostHeader string, hostHeaderExpected string) {
	ssoReqHostHeader := ""
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ssoReqHostHeader = r.Header.Get("x-forwarded-host")

		w.Header().Set("content-type", "text/html")
		w.WriteHeader(401)
		_, err := fmt.Fprint(w, "I couldn't find correct cookie or authorization headers")
		if err != nil {
			t.Fatal(err)
		}
	}))
	defer s.Close()

	f := ForwardAuth{
		Url:         s.URL,
		restyClient: resty.New(),
	}

	nextCalled := false
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://localhost/path", nil)
	if hostHeader != "" {
		req.Header.Set("host", hostHeader)
	}
	err := f.ServeHTTP(w, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		return nil
	}))

	assert.Nil(t, err, err)
	assert.Equal(t, hostHeaderExpected, ssoReqHostHeader)
	assert.Equal(t, false, nextCalled)

	result := w.Result()
	body, err := io.ReadAll(result.Body)
	assert.Equal(t, result.StatusCode, 401)
	assert.Equal(t, "text/html", result.Header.Get("content-type"))
	assert.Equal(t, "I couldn't find correct cookie or authorization headers", string(body))
}
