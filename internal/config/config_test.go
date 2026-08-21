package config

import (
	"net/url"
	"testing"

	"github.com/writer/aperio/internal/runtimeutil"
)

func TestFromEnvDerivesPGXSafeDatabaseURL(t *testing.T) {
	const raw = "postgresql://127.0.0.1:5433/aperio?schema=public&connection_limit=5"
	t.Setenv("DATABASE_URL", raw)

	cfg := FromEnv()
	parsed, err := url.Parse(cfg.DatabaseURL)
	if err != nil {
		t.Fatalf("parse database URL: %v", err)
	}
	query := parsed.Query()
	if query.Has("schema") || query.Has("connection_limit") {
		t.Fatalf("Prisma-only query params were not removed: %s", runtimeutil.RedactDSN(cfg.DatabaseURL))
	}
	if query.Get("sslmode") != "disable" {
		t.Fatalf("sslmode = %q, want disable", query.Get("sslmode"))
	}
}

func TestFromEnvReadsMetricsToken(t *testing.T) {
	t.Setenv("APERIO_METRICS_TOKEN", "  metrics-secret  ")

	cfg := FromEnv()
	if cfg.MetricsToken != "metrics-secret" {
		t.Fatalf("MetricsToken = %q, want trimmed token", cfg.MetricsToken)
	}
}
