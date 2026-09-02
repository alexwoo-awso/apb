// Package httpx holds the transport-level concerns shared by the device API
// and the admin console: client address resolution, security headers, request
// logging and rate limiting.
package httpx

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type ctxKey int

const (
	ctxClientIP ctxKey = iota
	ctxRequestID
)

// ClientIP returns the address resolved by RealIP.
func ClientIP(r *http.Request) string {
	if v, ok := r.Context().Value(ctxClientIP).(string); ok {
		return v
	}
	return hostOnly(r.RemoteAddr)
}

func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// RealIP resolves the client address once per request. Forwarded headers are
// honoured only when the deployment explicitly says it sits behind a proxy;
// otherwise an attacker could forge their own address and defeat rate limits.
func RealIP(trustProxy bool, header string) func(http.Handler) http.Handler {
	if header == "" {
		header = "X-Forwarded-For"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := hostOnly(r.RemoteAddr)
			if trustProxy {
				if v := r.Header.Get(header); v != "" {
					// The left-most entry is the originating client.
					if i := strings.IndexByte(v, ','); i >= 0 {
						v = v[:i]
					}
					if v = strings.TrimSpace(v); v != "" {
						ip = hostOnly(v)
					}
				}
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxClientIP, ip)))
		})
	}
}

// SecurityHeaders applies a deny-by-default policy. The console ships no
// third-party scripts, styles or fonts, so the policy can stay this tight.
func SecurityHeaders(hsts bool) func(http.Handler) http.Handler {
	const csp = "default-src 'none'; " +
		"script-src 'self'; " +
		"style-src 'self'; " +
		"img-src 'self' data:; " +
		"font-src 'self'; " +
		"connect-src 'self'; " +
		"form-action 'self'; " +
		"frame-ancestors 'none'; " +
		"base-uri 'none'; " +
		"object-src 'none'"
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Content-Security-Policy", csp)
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "same-origin")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=(), usb=(), interest-cohort=()")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			if hsts {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// statusWriter records the response status and size for logging.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

// Logger emits one structured line per request.
func Logger(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w}
			next.ServeHTTP(sw, r)
			if sw.status == 0 {
				sw.status = http.StatusOK
			}
			level := slog.LevelInfo
			switch {
			case sw.status >= 500:
				level = slog.LevelError
			case sw.status >= 400:
				level = slog.LevelWarn
			case r.URL.Path == "/healthz" || sw.status == http.StatusNoContent:
				level = slog.LevelDebug // the 15-second poll must not flood the log
			}
			log.Log(r.Context(), level, "http",
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"bytes", sw.bytes,
				"ip", ClientIP(r),
				"ms", time.Since(start).Milliseconds())
		})
	}
}

// Recover turns a panic into a 500 instead of dropping the connection, and
// logs the stack once.
func Recover(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if v := recover(); v != nil {
					if v == http.ErrAbortHandler {
						panic(v)
					}
					log.Error("panic serving request", "path", r.URL.Path, "err", v)
					http.Error(w, "internal error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// MaxBody rejects oversized request bodies before they are read.
func MaxBody(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, n)
			next.ServeHTTP(w, r)
		})
	}
}

// Chain composes middleware so that the first argument is the outermost.
func Chain(h http.Handler, mw ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// ---------------------------------------------------------------- rate limit

// Limiter is a fixed-cost token bucket keyed by an arbitrary string, used for
// login attempts and for API traffic. It is intentionally in-memory: the
// service is a single process, and persisting counters would cost a write per
// request on the hot path.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   float64
	last    time.Time
}

type bucket struct {
	tokens float64
	seen   time.Time
}

// NewLimiter builds a limiter allowing burst requests immediately and rate
// requests per second thereafter.
func NewLimiter(rate, burst float64) *Limiter {
	return &Limiter{buckets: map[string]*bucket{}, rate: rate, burst: burst, last: time.Now()}
}

// Allow consumes one token for key, reporting whether the request may proceed.
func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.last) > 10*time.Minute {
		l.gc(now)
		l.last = now
	}
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, seen: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.seen).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.seen = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Reset clears the bucket for a key, called after a successful login so a user
// who mistyped a password is not held back.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	delete(l.buckets, key)
	l.mu.Unlock()
}

func (l *Limiter) gc(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.seen) > 30*time.Minute {
			delete(l.buckets, k)
		}
	}
}

// RateLimit rejects requests over the limit with 429 and a Retry-After hint.
func RateLimit(l *Limiter, keyFn func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !l.Allow(keyFn(r)) {
				w.Header().Set("Retry-After", "5")
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
