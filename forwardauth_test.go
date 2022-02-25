package forwardauth

import (
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestForAuth200(t *testing.T) {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	f := ForwardAuth{
		ForwardAuthUrl: ts.URL,
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
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		_, err := w.Write([]byte("I couldn't find correct cookie or authorization headers"))
		if err != nil {
			t.Fatal(err)
		}
	}))
	defer ts.Close()

	f := ForwardAuth{
		ForwardAuthUrl: ts.URL,
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

	//result, err := io.ReadAll(w.Result().Body)
	assert.Equal(t, w.Result().StatusCode, 401)
	//assert.Equal(t, "I couldn't find correct cookie or authorization headers", string(result))
}
