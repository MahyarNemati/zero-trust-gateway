// Package metrics defines the gateway's Prometheus instruments.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds every instrument on its own registry.
type Metrics struct {
	Registry        *prometheus.Registry
	Decisions       *prometheus.CounterVec
	AuthEvents      *prometheus.CounterVec
	UpstreamLatency *prometheus.HistogramVec
	PolicyReloads   *prometheus.CounterVec
	SessionRefresh  *prometheus.CounterVec
	KeyRotations    prometheus.Counter
}

// New registers the instruments, plus Go runtime and process collectors.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		Registry: reg,
		Decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "zt_policy_decisions_total", Help: "Policy decisions by route and outcome.",
		}, []string{"route", "outcome"}),
		AuthEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "zt_auth_events_total", Help: "Authentication events by type and result.",
		}, []string{"event", "result"}),
		UpstreamLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "zt_upstream_request_duration_seconds", Help: "Latency of proxied requests by status class.",
			Buckets: prometheus.DefBuckets,
		}, []string{"code"}),
		PolicyReloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "zt_policy_reloads_total", Help: "Policy file reloads by result.",
		}, []string{"result"}),
		SessionRefresh: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "zt_session_refresh_total", Help: "IdP token refreshes by result.",
		}, []string{"result"}),
		KeyRotations: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "zt_signing_key_rotations_total", Help: "Upstream signing key rotations.",
		}),
	}
	reg.MustRegister(m.Decisions, m.AuthEvents, m.UpstreamLatency, m.PolicyReloads, m.SessionRefresh, m.KeyRotations,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// Handler serves the registry in the Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{Registry: m.Registry})
}

// Result maps an error to a metric label.
func Result(err error) string {
	if err != nil {
		return "error"
	}
	return "ok"
}
