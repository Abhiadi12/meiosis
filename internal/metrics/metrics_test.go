package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func render(t *testing.T, r *Registry) string {
	t.Helper()
	var sb strings.Builder
	if _, err := r.WriteTo(&sb); err != nil {
		t.Fatal(err)
	}
	return sb.String()
}

func TestRenderingIsTheExpositionFormat(t *testing.T) {
	r := NewRegistry()
	req := r.Counter("meiosis_requests_total", "Requests served.", "route", "code")
	req.Inc("git", "200")
	req.Inc("git", "200")
	req.Add(3, "mcp", "401")
	h := r.Histogram("meiosis_latency_seconds", "Latency.", []float64{0.1, 1}, "route")
	h.Observe(0.05, "git")
	h.Observe(0.5, "git")
	h.Observe(5, "git")
	r.SetGauge("meiosis_up", "Whether it is up.", 1, nil)

	want := `# HELP meiosis_latency_seconds Latency.
# TYPE meiosis_latency_seconds histogram
meiosis_latency_seconds_bucket{route="git",le="0.1"} 1
meiosis_latency_seconds_bucket{route="git",le="1"} 2
meiosis_latency_seconds_bucket{route="git",le="+Inf"} 3
meiosis_latency_seconds_sum{route="git"} 5.55
meiosis_latency_seconds_count{route="git"} 3
# HELP meiosis_requests_total Requests served.
# TYPE meiosis_requests_total counter
meiosis_requests_total{route="git",code="200"} 2
meiosis_requests_total{route="mcp",code="401"} 3
# HELP meiosis_up Whether it is up.
# TYPE meiosis_up gauge
meiosis_up 1
`
	if got := render(t, r); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestLabelValuesAreEscapedAndNegativeCountersIgnored(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("x_total", "x", "v")
	c.Inc("quote\" back\\slash\nnewline")
	c.Add(-5, "ignored")
	out := render(t, r)
	if !strings.Contains(out, `x_total{v="quote\" back\\slash\nnewline"} 1`) || strings.Contains(out, "ignored") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestSeriesAreSharedPerLabelValuesAndSafeConcurrently(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("c_total", "c", "k")
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			for j := 0; j < 500; j++ {
				c.Inc("a")
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if out := render(t, r); !strings.Contains(out, `c_total{k="a"} 4000`) {
		t.Fatalf("lost increments:\n%s", out)
	}
	if again := r.Counter("c_total", "c", "k"); again.f != c.f {
		t.Fatal("registering the same family twice made two")
	}
}

func TestHandlerServesLoopbackOnly(t *testing.T) {
	r := NewRegistry()
	r.SetGauge("meiosis_up", "up", 1, nil)
	h := r.Handler(false)
	for remote, want := range map[string]int{"127.0.0.1:5555": 200, "[::1]:5555": 200, "203.0.113.9:5555": 403, "10.1.2.3:80": 403} {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("%s: %d, want %d", remote, rec.Code, want)
		}
		if want == 200 && (!strings.Contains(rec.Body.String(), "meiosis_up 1") || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain; version=0.0.4")) {
			t.Errorf("%s: body %q type %q", remote, rec.Body.String(), rec.Header().Get("Content-Type"))
		}
	}
	remote := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	remote.RemoteAddr = "203.0.113.9:1"
	rec := httptest.NewRecorder()
	r.Handler(true).ServeHTTP(rec, remote)
	if rec.Code != 200 {
		t.Errorf("allowRemote: %d", rec.Code)
	}
}
