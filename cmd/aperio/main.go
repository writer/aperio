package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/writer/aperio/internal/bootstrap"
	"github.com/writer/aperio/internal/cerebroclient"
	"github.com/writer/aperio/internal/config"
)

// main is the production entrypoint for the Go/ConnectRPC backend. It is kept
// separate from the existing Express server so Aperio can shift read paths to Go
// incrementally while both runtimes share Postgres and cookie sessions.
func main() {
	cfg := config.FromEnv()
	if cfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}
	// pgx's stdlib driver gives database/sql pooling while keeping the codebase
	// ready for lower-level pgx usage as more endpoints move to Go.
	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(time.Duration(cfg.ConnMaxLifetimeMinutes) * time.Minute)
	db.SetConnMaxIdleTime(time.Duration(cfg.ConnMaxIdleMinutes) * time.Minute)
	pingCtx, cancelPing := context.WithTimeout(context.Background(), 5*time.Second)
	if err := db.PingContext(pingCtx); err != nil {
		cancelPing()
		_ = db.Close()
		log.Fatal(err)
	}
	cancelPing()

	cerebroCfg := cerebroclient.ConfigFromEnv()
	cerebroCtx, cancelCerebro := context.WithTimeout(context.Background(), cerebroCfg.Timeout)
	runtime, cerebroEnabled, err := ensureCerebroRuntime(cerebroCtx, cerebroCfg)
	cancelCerebro()
	if err != nil {
		_ = db.Close()
		log.Fatalf("Cerebro runtime ensure failed: %v", err)
	}
	if cerebroEnabled {
		log.Printf(
			"Cerebro source runtime ensured id=%s tenant=%s source=%s",
			runtime.ID,
			runtime.TenantID,
			runtime.SourceID,
		)
	}

	app := bootstrap.NewApp(cfg, db)
	if cerebroEnabled {
		cerebroClient, err := cerebroclient.New(cerebroCfg)
		if err != nil {
			_ = db.Close()
			log.Fatalf("Cerebro client setup failed: %v", err)
		}
		app.WithCerebroContextClient(runtime.ID, cerebroClient).WithCerebroMCPServerURL(cerebroCfg.MCPServerURL())
	}
	// The service intentionally uses the standard net/http server that ConnectRPC
	// generates handlers for; this mirrors Cerebro's lightweight server wiring.
	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("Aperio Go Connect service listening on %s", cfg.Addr)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelShutdown()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("Aperio Go Connect graceful shutdown failed: %v", err)
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			_ = db.Close()
			log.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		log.Printf("database close failed: %v", err)
	}
}
