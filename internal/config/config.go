package config

import (
	"os"
	"strconv"
	"strings"

	"github.com/writer/aperio/internal/runtimeutil"
)

// Config contains the small runtime surface the Go service needs today. It is
// intentionally independent from the TypeScript API config so the new backend
// can be deployed, scaled, and rolled back as its own process.
type Config struct {
	// Addr is the HTTP listen address for the ConnectRPC server.
	Addr string
	// DatabaseURL points at the same Postgres database used by the TypeScript API.
	DatabaseURL string
	// SessionIdleMinutes mirrors APERIO_SESSION_IDLE_MINUTES from the TypeScript API.
	SessionIdleMinutes int
	// WebOrigin is the comma-separated browser origin allow-list used for credentialed RPCs.
	WebOrigin              string
	CerebroWebURL          string
	MaxOpenConns           int
	MaxIdleConns           int
	ConnMaxLifetimeMinutes int
	ConnMaxIdleMinutes     int
}

// FromEnv reads process configuration with local-development defaults. Required
// values, such as DATABASE_URL, are validated by cmd/aperio so tests can build a
// Config without a database.
func FromEnv() Config {
	_, _ = runtimeutil.LoadLocalEnv(false)
	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if safeURL, err := runtimeutil.PGXSafeDatabaseURL(databaseURL); err == nil {
		databaseURL = safeURL
	}
	return Config{
		Addr:               env("APERIO_CONNECT_ADDR", ":4100"),
		DatabaseURL:        databaseURL,
		SessionIdleMinutes: envInt("APERIO_SESSION_IDLE_MINUTES", 120),
		WebOrigin:          strings.TrimRight(env("APERIO_WEB_ORIGIN", "http://localhost:3000"), "/"),
		CerebroWebURL:      env("CEREBRO_WEB_URL", ""),
		MaxOpenConns:       envInt("APERIO_CONNECT_DB_MAX_OPEN_CONNS", 10),
		MaxIdleConns:       envInt("APERIO_CONNECT_DB_MAX_IDLE_CONNS", 5),
		ConnMaxLifetimeMinutes: envInt(
			"APERIO_CONNECT_DB_CONN_MAX_LIFETIME_MINUTES",
			30,
		),
		ConnMaxIdleMinutes: envInt("APERIO_CONNECT_DB_CONN_MAX_IDLE_MINUTES", 5),
	}
}

// env returns a trimmed environment variable or a fallback when unset. Keeping
// trimming centralized prevents subtle CORS and listen-address mismatches.
func env(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

// envInt parses integer settings with the same forgiving local-development
// behavior as env: invalid or missing values fall back to a safe default.
func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}
