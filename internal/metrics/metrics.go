// Package metrics is a small Prometheus-compatible metrics registry. It writes
// the text exposition format (version 0.0.4) by hand, so serving metrics costs
// no dependency (SRS RK-8); it implements only what meiosis uses: counters,
// histograms and gauges with labels.
package metrics

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// Registry holds metric families and renders them.
type Registry struct {
	mu       sync.Mutex
	families map[string]*family
}

type kind int

const (
	counterKind kind = iota
	histogramKind
	gaugeKind
)

type family struct {
	name, help string
	kind       kind
	labels     []string
	buckets    []float64
	series     map[string]*series
}

type series struct {
	labelValues []string
	value       float64  // counter / gauge
	counts      []uint64 // histogram: per bucket, cumulative at render time
	sum         float64
	count       uint64
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{families: map[string]*family{}} }

func (r *Registry) register(name, help string, k kind, labels []string, buckets []float64) *family {
	r.mu.Lock()
	defer r.mu.Unlock()
	if f, ok := r.families[name]; ok {
		return f
	}
	f := &family{name: name, help: help, kind: k, labels: labels, buckets: buckets, series: map[string]*series{}}
	r.families[name] = f
	return f
}

// Counter is a monotonically increasing value, split by label values.
type Counter struct {
	r *Registry
	f *family
}

// Counter registers (or returns) a counter family.
func (r *Registry) Counter(name, help string, labels ...string) *Counter {
	return &Counter{r: r, f: r.register(name, help, counterKind, labels, nil)}
}

// Inc adds one for the given label values.
func (c *Counter) Inc(labelValues ...string) { c.Add(1, labelValues...) }

// Add adds v (which must not be negative) for the given label values.
func (c *Counter) Add(v float64, labelValues ...string) {
	if v < 0 {
		return
	}
	c.r.mu.Lock()
	defer c.r.mu.Unlock()
	c.f.get(labelValues).value += v
}

// Histogram observes values into buckets.
type Histogram struct {
	r *Registry
	f *family
}

// DefaultBuckets suit request latencies in seconds.
var DefaultBuckets = []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// Histogram registers (or returns) a histogram family.
func (r *Registry) Histogram(name, help string, buckets []float64, labels ...string) *Histogram {
	if buckets == nil {
		buckets = DefaultBuckets
	}
	return &Histogram{r: r, f: r.register(name, help, histogramKind, labels, buckets)}
}

// Observe records one value for the given label values.
func (h *Histogram) Observe(v float64, labelValues ...string) {
	h.r.mu.Lock()
	defer h.r.mu.Unlock()
	s := h.f.get(labelValues)
	if s.counts == nil {
		s.counts = make([]uint64, len(h.f.buckets))
	}
	for i, b := range h.f.buckets {
		if v <= b {
			s.counts[i]++
			break
		}
	}
	s.sum += v
	s.count++
}

// SetGauge sets a gauge for the given label values.
func (r *Registry) SetGauge(name, help string, value float64, labelNames []string, labelValues ...string) {
	f := r.register(name, help, gaugeKind, labelNames, nil)
	r.mu.Lock()
	defer r.mu.Unlock()
	f.get(labelValues).value = value
}

func (f *family) get(labelValues []string) *series {
	// A mismatch is a programming error; pad or cut so rendering never breaks.
	vals := make([]string, len(f.labels))
	copy(vals, labelValues)
	key := strings.Join(vals, "\x00")
	s, ok := f.series[key]
	if !ok {
		s = &series{labelValues: vals}
		f.series[key] = s
	}
	return s
}

// WriteTo renders every family in the Prometheus text format, sorted so output
// is stable.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, 0, len(r.families))
	for n := range r.families {
		names = append(names, n)
	}
	sort.Strings(names)
	var sb strings.Builder
	for _, n := range names {
		f := r.families[n]
		typ := map[kind]string{counterKind: "counter", histogramKind: "histogram", gaugeKind: "gauge"}[f.kind]
		fmt.Fprintf(&sb, "# HELP %s %s\n# TYPE %s %s\n", f.name, escapeHelp(f.help), f.name, typ)
		keys := make([]string, 0, len(f.series))
		for k := range f.series {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			s := f.series[k]
			switch f.kind {
			case histogramKind:
				var cum uint64
				for i, b := range f.buckets {
					if s.counts != nil {
						cum += s.counts[i]
					}
					fmt.Fprintf(&sb, "%s_bucket%s %d\n", f.name, labelString(f.labels, s.labelValues, "le", formatFloat(b)), cum)
				}
				fmt.Fprintf(&sb, "%s_bucket%s %d\n", f.name, labelString(f.labels, s.labelValues, "le", "+Inf"), s.count)
				fmt.Fprintf(&sb, "%s_sum%s %s\n", f.name, labelString(f.labels, s.labelValues, "", ""), formatFloat(s.sum))
				fmt.Fprintf(&sb, "%s_count%s %d\n", f.name, labelString(f.labels, s.labelValues, "", ""), s.count)
			default:
				fmt.Fprintf(&sb, "%s%s %s\n", f.name, labelString(f.labels, s.labelValues, "", ""), formatFloat(s.value))
			}
		}
	}
	n, err := io.WriteString(w, sb.String())
	return int64(n), err
}

// Handler serves the registry. Metrics describe the server, not the data in it,
// but they are still not for the open internet: only loopback clients are served
// unless allowRemote is set.
func (r *Registry) Handler(allowRemote bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !allowRemote && !isLoopback(req.RemoteAddr) {
			http.Error(w, "metrics are served to loopback clients only", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = r.WriteTo(w)
	})
}

func isLoopback(remote string) bool {
	host := remote
	if i := strings.LastIndex(remote, ":"); i >= 0 {
		host = remote[:i]
	}
	host = strings.Trim(host, "[]")
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

func labelString(names, values []string, extraName, extraValue string) string {
	if len(names) == 0 && extraName == "" {
		return ""
	}
	parts := make([]string, 0, len(names)+1)
	for i, n := range names {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, n, escapeLabel(values[i])))
	}
	if extraName != "" {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, extraName, extraValue))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func formatFloat(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return fmt.Sprintf("%g", v)
}
