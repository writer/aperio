package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/writer/aperio/internal/bootstrap"
	"github.com/writer/aperio/internal/config"
	"github.com/writer/aperio/internal/googleworkspacepoller"
)

func main() {
	once := flag.Bool("once", false, "tick once and exit")
	interval := flag.Duration("interval", 5*time.Minute, "poll interval between sweeps")
	flag.Parse()

	cfg := config.FromEnv()
	if cfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}
	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(time.Duration(cfg.ConnMaxLifetimeMinutes) * time.Minute)
	db.SetConnMaxIdleTime(time.Duration(cfg.ConnMaxIdleMinutes) * time.Minute)

	poller := googleworkspacepoller.NewBigQueryPoller(db).WithInterval(*interval)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *once {
		if err := poller.Tick(ctx); err != nil {
			log.Fatalf("google-workspace-bigquery-sync: tick failed: %v", err)
		}
		return
	}

	go runWakeListener(ctx, cfg.DatabaseURL, poller)
	log.Printf("google-workspace-bigquery-sync: starting (interval=%s, wake-channel=%s)", *interval, bootstrap.GoogleWorkspaceBigQuerySyncWakeChannel)
	if err := poller.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("google-workspace-bigquery-sync: %v", err)
	}
}

func runWakeListener(ctx context.Context, dsn string, poller *googleworkspacepoller.BigQueryPoller) {
	for {
		if err := listenOnce(ctx, dsn, poller); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("google-workspace-bigquery-sync: listener failed: %v", err)
			timer := time.NewTimer(5 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}
}

func listenOnce(ctx context.Context, dsn string, poller *googleworkspacepoller.BigQueryPoller) error {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("listener connect: %w", err)
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{bootstrap.GoogleWorkspaceBigQuerySyncWakeChannel}.Sanitize()); err != nil {
		return fmt.Errorf("LISTEN %s: %w", bootstrap.GoogleWorkspaceBigQuerySyncWakeChannel, err)
	}
	for {
		notification, err := conn.WaitForNotification(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		integrationID := strings.TrimSpace(notification.Payload)
		if integrationID == "" {
			continue
		}
		go func() {
			if err := poller.WakeIntegration(ctx, integrationID); err != nil {
				log.Printf("google-workspace-bigquery-sync: wake integration %s failed: %v", integrationID, err)
			}
		}()
	}
}
