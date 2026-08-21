package telemetry

import (
	"strings"
	"testing"
)

func resetPrometheusRegistryForTest() func() {
	prometheusRegistry.Lock()
	previousCounters := prometheusRegistry.counters
	previousGauges := prometheusRegistry.gauges
	prometheusRegistry.counters = map[string]map[string]float64{}
	prometheusRegistry.gauges = map[string]map[string]float64{}
	prometheusRegistry.Unlock()
	return func() {
		prometheusRegistry.Lock()
		prometheusRegistry.counters = previousCounters
		prometheusRegistry.gauges = previousGauges
		prometheusRegistry.Unlock()
	}
}

func TestPrometheusLabelsCollapseUnboundedValues(t *testing.T) {
	restore := resetPrometheusRegistryForTest()
	defer restore()

	IncCounter("aperio_test_events_total", map[string]string{
		"provider": "tenant-" + strings.Repeat("x", 200),
		"route":    "/organizations/secret-resource-id",
	})
	output := RenderPrometheus()
	if !strings.Contains(output, `aperio_test_events_total{provider="other"} 1`) {
		t.Fatalf("bounded metric output = %q", output)
	}
	if strings.Contains(output, "secret-resource-id") || strings.Contains(output, "tenant-") {
		t.Fatalf("unbounded label value leaked into metric output: %q", output)
	}
}

func TestPrometheusOutputIsDeterministicAndTyped(t *testing.T) {
	restore := resetPrometheusRegistryForTest()
	defer restore()

	IncCounter("aperio_rule_runs_total", map[string]string{"provider": "SLACK", "outcome": "succeeded"})
	SetGauge("aperio_ingestion_queue_jobs", 3, map[string]string{"status": "QUEUED"})
	output := RenderPrometheus()
	if !strings.Contains(output, "# TYPE aperio_rule_runs_total counter\n") {
		t.Fatalf("missing counter type: %q", output)
	}
	if !strings.Contains(output, "# TYPE aperio_ingestion_queue_jobs gauge\n") {
		t.Fatalf("missing gauge type: %q", output)
	}
	if !strings.Contains(output, `aperio_ingestion_queue_jobs{status="QUEUED"} 3`) {
		t.Fatalf("missing gauge sample: %q", output)
	}
}

func TestPrometheusGaugeSnapshotRemovesDrainedLabels(t *testing.T) {
	restore := resetPrometheusRegistryForTest()
	defer restore()

	ReplaceGaugeSnapshot("aperio_ingestion_queue_jobs", "status", map[string]float64{"QUEUED": 4, "DEAD_LETTER": 1})
	if output := RenderPrometheus(); !strings.Contains(output, `status="QUEUED"} 4`) {
		t.Fatalf("initial gauge snapshot = %q", output)
	}
	ReplaceGaugeSnapshot("aperio_ingestion_queue_jobs", "status", map[string]float64{"SUCCEEDED": 2})
	output := RenderPrometheus()
	if strings.Contains(output, `status="QUEUED"`) || strings.Contains(output, `status="DEAD_LETTER"`) {
		t.Fatalf("stale drained labels retained: %q", output)
	}
	if !strings.Contains(output, `status="SUCCEEDED"} 2`) {
		t.Fatalf("replacement gauge snapshot = %q", output)
	}
}
