package mtasts

import (
	"errors"
	"mime"
	"net/http"
	"time"
)

var httpClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return errors.New("mtasts: HTTP redirects are forbidden")
	},
	Timeout: time.Minute,
}

func DownloadPolicy(domain string) (*Policy, error) {
	resp, err := httpClient.Get("https://mta-sts." + domain + "/.well-known/mta-sts.txt")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Policies fetched via HTTPS are only valid if the HTTP response code is
	// 200 (OK).  HTTP 3xx redirects MUST NOT be followed.
	if resp.StatusCode != 200 {
		return nil, errors.New("mtasts: HTTP " + resp.Status)
	}

	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}

	if contentType != "text/plain" {
		return nil, errors.New("mtasts: unexpected content type")
	}

	return readPolicy(resp.Body)
}
