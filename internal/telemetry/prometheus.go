package telemetry

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// The registry intentionally accepts only bounded label vocabularies. Tenant,
// integration, event, and resource identifiers must never become Prometheus
// labels; those belong in the authenticated operator health response or logs.
var prometheusRegistry = struct {
	sync.Mutex
	counters map[string]map[string]float64
	gauges   map[string]map[string]float64
}{
	counters: map[string]map[string]float64{},
	gauges:   map[string]map[string]float64{},
}

var allowedMetricLabels = map[string]map[string]struct{}{
	"kind": {
		"connector_sync": {}, "rule_run": {}, "ingestion": {}, "siem": {}, "other": {},
	},
	"outcome": {
		"started": {}, "succeeded": {}, "failed": {}, "dead_letter": {}, "delivered": {}, "retryable_failed": {}, "timeout": {}, "lost_lease": {}, "other": {},
	},
	"provider": {
		"GITHUB": {}, "SLACK": {}, "GOOGLE_WORKSPACE": {}, "OKTA": {}, "MICROSOFT_365": {},
		"ATLASSIAN": {}, "SALESFORCE": {}, "ONE_PASSWORD": {}, "other": {},
	},
	"source": {
		"google_workspace_reports": {}, "google_workspace_bigquery": {},
		"google_workspace_directory": {}, "google_workspace_oauth": {}, "other": {},
	},
	"status": {
		"QUEUED": {}, "RUNNING": {}, "FAILED": {}, "DEAD_LETTER": {}, "SUCCEEDED": {},
		"PENDING": {}, "PROCESSING": {}, "DELIVERED": {}, "other": {},
	},
	"stream": {"FINDINGS": {}, "EVENTS": {}, "AUDIT_LOGS": {}, "other": {}},
}

// IncCounter increments a process-local counter. Values are rendered in
// Prometheus text format by RenderPrometheus; label keys/values outside the
// bounded vocabulary are collapsed to "other".
func IncCounter(name string, labels map[string]string) {
	name = metricName(name)
	if name == "" {
		return
	}
	key := labelKey(labels)
	prometheusRegistry.Lock()
	defer prometheusRegistry.Unlock()
	if prometheusRegistry.counters[name] == nil {
		prometheusRegistry.counters[name] = map[string]float64{}
	}
	prometheusRegistry.counters[name][key]++
}

// SetGauge sets a process-local gauge with bounded labels.
func SetGauge(name string, value float64, labels map[string]string) {
	name = metricName(name)
	if name == "" {
		return
	}
	key := labelKey(labels)
	prometheusRegistry.Lock()
	defer prometheusRegistry.Unlock()
	if prometheusRegistry.gauges[name] == nil {
		prometheusRegistry.gauges[name] = map[string]float64{}
	}
	prometheusRegistry.gauges[name][key] = value
}

// ReplaceGaugeSnapshot replaces every series for a gauge in one operation.
// Callers that aggregate a database table should use this instead of SetGauge
// so labels that disappeared from the latest snapshot cannot retain stale
// non-zero values forever.
func ReplaceGaugeSnapshot(name, labelName string, values map[string]float64) {
	name = metricName(name)
	if name == "" {
		return
	}
	series := make(map[string]float64, len(values))
	for labelValue, value := range values {
		key := labelKey(map[string]string{labelName: labelValue})
		series[key] += value
	}
	prometheusRegistry.Lock()
	defer prometheusRegistry.Unlock()
	prometheusRegistry.gauges[name] = series
}

// RenderPrometheus returns a complete Prometheus text exposition. A stable
// trailing newline and deterministic ordering make scrape output easy to diff
// and test.
func RenderPrometheus() string {
	prometheusRegistry.Lock()
	defer prometheusRegistry.Unlock()
	var builder strings.Builder
	names := make([]string, 0, len(prometheusRegistry.counters)+len(prometheusRegistry.gauges))
	seen := map[string]struct{}{}
	for name := range prometheusRegistry.counters {
		seen[name] = struct{}{}
		names = append(names, name)
	}
	for name := range prometheusRegistry.gauges {
		if _, ok := seen[name]; !ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if values, ok := prometheusRegistry.counters[name]; ok {
			fmt.Fprintf(&builder, "# TYPE %s counter\n", name)
			renderValues(&builder, name, values)
		}
		if values, ok := prometheusRegistry.gauges[name]; ok {
			fmt.Fprintf(&builder, "# TYPE %s gauge\n", name)
			renderValues(&builder, name, values)
		}
	}
	return builder.String()
}

func renderValues(builder *strings.Builder, name string, values map[string]float64) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key == "" {
			fmt.Fprintf(builder, "%s %v\n", name, values[key])
			continue
		}
		fmt.Fprintf(builder, "%s{%s} %v\n", name, key, values[key])
	}
}

func metricName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	for _, char := range name {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '_' && char != ':' {
			return ""
		}
	}
	return name
}

func labelKey(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		if _, ok := allowedMetricLabels[key]; ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		value := labels[key]
		if _, ok := allowedMetricLabels[key][value]; !ok {
			value = "other"
		}
		parts = append(parts, fmt.Sprintf(`%s="%s"`, key, escapeLabel(value)))
	}
	return strings.Join(parts, ",")
}

func escapeLabel(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return strings.ReplaceAll(value, "\n", `\n`)
}
