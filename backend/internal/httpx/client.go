package httpx

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

type Client struct {
	hc       *http.Client
	limiter  *rate.Limiter
	ua       string
	maxRetry int
}

func New(throttleMS, maxRetry int, ua string) *Client {
	interval := time.Duration(throttleMS) * time.Millisecond
	if interval <= 0 {
		interval = time.Millisecond
	}
	return &Client{
		hc:       &http.Client{Timeout: 60 * time.Second},
		limiter:  rate.NewLimiter(rate.Every(interval), 1),
		ua:       ua,
		maxRetry: maxRetry,
	}
}

func (c *Client) Do(ctx context.Context, method, url string, headers map[string]string, body []byte) (int, []byte, error) {
	var lastErr error
	backoff := 3 * time.Second
	for attempt := 0; attempt <= c.maxRetry; attempt++ {
		if err := c.limiter.Wait(ctx); err != nil {
			return 0, nil, err
		}
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, rdr)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("User-Agent", c.ua)
		if _, ok := headers["Accept"]; !ok {
			req.Header.Set("Accept", "application/json")
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(backoff)
			backoff *= 2
			continue
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("http %d: %s", resp.StatusCode, snippet(data))
			wait := backoff
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if d, e := time.ParseDuration(ra + "s"); e == nil {
					wait = d
				}
			}
			time.Sleep(wait)
			backoff *= 2
			continue
		}
		return resp.StatusCode, data, nil
	}
	return 0, nil, fmt.Errorf("max retry asildi: %w", lastErr)
}

func snippet(b []byte) string {
	if len(b) > 160 {
		return string(b[:160])
	}
	return string(b)
}
