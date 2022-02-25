package forwardauth

import (
	"fmt"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestForAuth200(t *testing.T) {

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer s.Close()

	f := ForwardAuth{
		ForwardAuthUrl: s.URL,
	}

	nextCalled := false
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "localhost:80", nil)
	err := f.ServeHTTP(w, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		nextCalled = true
		return nil
	}))

	assert.Nil(t, err, "ServeHTTP has error")
	assert.Equal(t, true, nextCalled, "Next was not called")
}

func TestForNot200(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "text/html")
		w.WriteHeader(401)
		_, err := fmt.Fprint(w, "I couldn't find correct cookie or authorization headers")
		if err != nil {
			t.Fatal(err)
		}
	}))
	defer s.Close()

	f := ForwardAuth{
		ForwardAuthUrl: s.URL,
	}

	nextCalled := false
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "localhost:80", nil)
	err := f.ServeHTTP(w, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		nextCalled = true
		return nil
	}))

	assert.Nil(t, err, err)
	assert.Equal(t, false, nextCalled, "Next was called, but it should not have been called")

	result := w.Result()
	body, err := io.ReadAll(result.Body)
	assert.Equal(t, result.StatusCode, 401)
	assert.Equal(t, "text/html", result.Header.Get("content-type"))
	assert.Equal(t, "I couldn't find correct cookie or authorization headers", string(body))
}
