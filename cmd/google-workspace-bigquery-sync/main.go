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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/writer/aperio/internal/bootstrap"
	"github.com/writer/aperio/internal/config"
	"github.com/writer/aperio/internal/googleworkspacepoller"
)

const onceDrainWindow = 2 * time.Second
const onceWakeWorkBudget = 60 * time.Second
const notificationPollInterval = 500 * time.Millisecond

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
		listener, listenErr := openWakeListener(ctx, cfg.DatabaseURL)
		if listenErr != nil {
			log.Printf("google-workspace-bigquery-sync: -once listener setup failed (manual wake-ups will be dropped): %v", listenErr)
		} else {
			defer listener.Close(context.Background())
		}
		if err := poller.Tick(ctx); err != nil {
			log.Fatalf("google-workspace-bigquery-sync: tick failed: %v", err)
		}
		if listener != nil {
			drainWakeNotifications(ctx, listener, poller)
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

func openWakeListener(ctx context.Context, dsn string) (*pgx.Conn, error) {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("listener connect: %w", err)
	}
	if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{bootstrap.GoogleWorkspaceBigQuerySyncWakeChannel}.Sanitize()); err != nil {
		_ = conn.Close(context.Background())
		return nil, fmt.Errorf("LISTEN %s: %w", bootstrap.GoogleWorkspaceBigQuerySyncWakeChannel, err)
	}
	return conn, nil
}

func listenOnce(ctx context.Context, dsn string, poller *googleworkspacepoller.BigQueryPoller) error {
	conn, err := openWakeListener(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	return dispatchWakeNotifications(ctx, conn, poller, ctx)
}

func drainWakeNotifications(ctx context.Context, conn *pgx.Conn, poller *googleworkspacepoller.BigQueryPoller) {
	deadline := time.Now().Add(onceWakeWorkBudget)
	idleSince := time.Now()
	listenerFailed := false
	var active atomic.Int64
	for {
		if listenerFailed && active.Load() == 0 {
			return
		}
		if active.Load() == 0 && !idleSince.IsZero() && time.Since(idleSince) >= onceDrainWindow {
			return
		}
		if time.Now().After(deadline) {
			log.Printf("google-workspace-bigquery-sync: -once exiting after %s; some wake-triggered syncs may not have completed", onceWakeWorkBudget)
			return
		}
		if listenerFailed {
			timer := time.NewTimer(notificationPollInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				log.Printf("google-workspace-bigquery-sync: -once interrupted before wake-triggered syncs completed: %v", ctx.Err())
				return
			case <-timer.C:
			}
			continue
		}
		waitCtx, stopWaiting := context.WithTimeout(ctx, notificationPollInterval)
		notification, err := conn.WaitForNotification(waitCtx)
		waitErr := waitCtx.Err()
		stopWaiting()
		if err != nil {
			if ctx.Err() != nil {
				log.Printf("google-workspace-bigquery-sync: -once interrupted before wake-triggered syncs completed: %v", ctx.Err())
				return
			}
			if waitErr != nil {
				if active.Load() == 0 && idleSince.IsZero() {
					idleSince = time.Now()
				}
				continue
			}
			if active.Load() > 0 {
				log.Printf("google-workspace-bigquery-sync: -once wake drain stopped listening while %d sync(s) finish: %v", active.Load(), err)
				listenerFailed = true
				continue
			}
			log.Printf("google-workspace-bigquery-sync: -once wake drain failed: %v", err)
			return
		}
		integrationID := strings.TrimSpace(notification.Payload)
		if integrationID == "" {
			continue
		}
		active.Add(1)
		idleSince = time.Time{}
		go func(id string) {
			defer active.Add(-1)
			if err := poller.WakeIntegration(ctx, id); err != nil {
				log.Printf("google-workspace-bigquery-sync: wake integration %s failed: %v", id, err)
			}
		}(integrationID)
	}
}

func dispatchWakeNotifications(listenCtx context.Context, conn *pgx.Conn, poller *googleworkspacepoller.BigQueryPoller, workCtx context.Context) error {
	for {
		notification, err := conn.WaitForNotification(listenCtx)
		if err != nil {
			if listenCtx.Err() != nil {
				return nil
			}
			return err
		}
		integrationID := strings.TrimSpace(notification.Payload)
		if integrationID == "" {
			continue
		}
		go func(id string) {
			if err := poller.WakeIntegration(workCtx, id); err != nil {
				log.Printf("google-workspace-bigquery-sync: wake integration %s failed: %v", id, err)
			}
		}(integrationID)
	}
}
