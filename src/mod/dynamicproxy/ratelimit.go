package dynamicproxy

import (
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// IpTable is a rate limiter implementation using sync.Map with atomic int64
type RequestCountPerIpTable struct {
	table sync.Map
}

// Increment the count of requests for a given IP and return the new count
func (t *RequestCountPerIpTable) Increment(ip string) int64 {
	v, _ := t.table.LoadOrStore(ip, new(int64))
	return atomic.AddInt64(v.(*int64), 1)
}

// Check if the IP is in the table and if it is, check if the count is over the limit.
// The count includes the current request, so a limit of N allows N requests per window
func (t *RequestCountPerIpTable) Exceeded(ip string, limit int64) bool {
	v, ok := t.table.Load(ip)
	if !ok {
		return false
	}
	count := atomic.LoadInt64(v.(*int64))
	return count > limit
}

// Get the count of requests for a given IP
func (t *RequestCountPerIpTable) GetCount(ip string) int64 {
	v, ok := t.table.Load(ip)
	if !ok {
		return 0
	}
	return atomic.LoadInt64(v.(*int64))
}

// Clear the IP table
func (t *RequestCountPerIpTable) Clear() {
	t.table.Range(func(key, value interface{}) bool {
		t.table.Delete(key)
		return true
	})
}

func (h *ProxyHandler) handleRateLimitRouting(w http.ResponseWriter, r *http.Request, pe *ProxyEndpoint) error {
	err := h.Parent.handleRateLimit(w, r, pe)
	if err != nil {
		h.Parent.logRequest(r, false, 429, "ratelimit", r.URL.Hostname(), "", pe)
	}
	return err
}

func (router *Router) handleRateLimit(w http.ResponseWriter, r *http.Request, pe *ProxyEndpoint) error {
	if pe.RateLimit <= 0 {
		//No usable limit set (e.g. 0 from a hand edited config file). Treat as
		//no limit instead of blocking every request
		return nil
	}

	//Resolve the client IP using the same trusted proxy gated logic as the access
	//control check, so a header supplied address can neither break the limiter nor
	//be spoofed to escape it
	ip := router.GetClientIPForEndpoint(r, pe)
	if ip == "" {
		//Unable to resolve the client IP. Default allow passthrough
		return nil
	}

	//Count per proxy rule and client, so each rule enforces its own limit
	//instead of all rules sharing one counter per IP (#1107)
	//Use the count returned by the increment, so concurrent requests cannot
	//all see each other's increments and get blocked below the limit
	counterKey := rateLimitCounterKey(pe, ip)
	requestCount := router.rateLimitCounter.Increment(counterKey)

	if requestCount > int64(pe.RateLimit) {
		w.WriteHeader(429)
		return errors.New("rate limit exceeded")
	}

	// log.Println("Rate limit check", ip, ipTable.GetCount(ip))

	return nil
}

// rateLimitCounterKey returns the rate limit counter key of a client IP on
// the given proxy rule
func rateLimitCounterKey(pe *ProxyEndpoint, ip string) string {
	if pe == nil {
		return ip
	}
	return pe.RootOrMatchingDomain + "|" + ip
}

// Start the ticker routine for reseting the rate limit counter every seconds
func (r *Router) startRateLimterCounterResetTicker() error {
	if r.rateLimterStop != nil {
		return errors.New("another rate limiter ticker already running")
	}
	tickerStopChan := make(chan bool)
	r.rateLimterStop = tickerStopChan

	counterResetTicker := time.NewTicker(1 * time.Second)
	go func() {
		for {
			select {
			case <-tickerStopChan:
				r.rateLimterStop = nil
				return
			case <-counterResetTicker.C:
				r.rateLimitCounter.Clear()
			}
		}
	}()

	return nil
}
