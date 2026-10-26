package common

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOfflineBlocksHTTP(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(200) }))
	defer s.Close()
	SetOffline(true)
	defer SetOffline(false)
	for _, c := range []*http.Client{HttpDownloadClient, HttpSaasClient, http.DefaultClient} {
		if _, e := c.Get(s.URL); e == nil {
			t.Fatal("offline request succeeded")
		}
	}
	if calls != 0 {
		t.Fatal("offline request reached network")
	}
}
