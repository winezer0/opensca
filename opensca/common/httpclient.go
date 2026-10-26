package common

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

type offlineTransport struct{ base http.RoundTripper }

func (t offlineTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("offline mode blocks network request: %s", r.URL.Host)
}

// SetOffline wraps every HTTP path used by the CLI before starting workers.
func SetOffline(enabled bool) {
	for _, client := range []*http.Client{HttpDownloadClient, HttpSaasClient, http.DefaultClient} {
		if enabled {
			if _, ok := client.Transport.(offlineTransport); !ok {
				base := client.Transport
				if base == nil {
					base = http.DefaultTransport
				}
				client.Transport = offlineTransport{base}
			}
		} else if t, ok := client.Transport.(offlineTransport); ok {
			client.Transport = t.base
		}
	}
}

var HttpDownloadClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConns:        50,
		MaxConnsPerHost:     50,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     30 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
	},
}

func SetHttpDownloadClient(do func(c *http.Client)) {
	if do != nil {
		do(HttpDownloadClient)
	}
}

var HttpSaasClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConns:        1,
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     30 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
	},
}

func SetHttpSaasClient(do func(c *http.Client)) {
	if do != nil {
		do(HttpSaasClient)
	}
}
