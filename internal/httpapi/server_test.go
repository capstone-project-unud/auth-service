package httpapi

import (
	"capstone/auth-service/internal/config"
	"capstone/auth-service/internal/store"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoginRateLimitAndInternalAccess(t *testing.T) {
	app := New(config.Config{InternalToken: strings.Repeat("s", 40)}, store.Store{})
	for i := 0; i < 11; i++ {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Client-IP", "test-client")
		res, e := app.Test(req)
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		want := 422
		if i == 10 {
			want = 429
		}
		if res.StatusCode != want {
			t.Fatalf("request %d status=%d expected=%d", i, res.StatusCode, want)
		}
	}
	req := httptest.NewRequest("POST", "/internal/sessions/verify", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	res, e := app.Test(req)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("private endpoint accepted missing service token")
	}
}
