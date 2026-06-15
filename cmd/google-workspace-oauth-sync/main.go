// google-workspace-oauth-sync pulls per-user OAuth grants from the Google
// Admin Directory tokens API and upserts them into security_assets +
// oauth_app_grants so the Shadow IT page stops showing zero OAuth apps
// for live tenants.
package main

import (
	"context"
	"database/sql"
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
	"github.com/writer/aperio/internal/googleworkspaceoauthsync"
)

const onceDrainWindow = 2 * time.Second
const onceWakeWorkBudget = 60 * time.Second
const notificationPollInterval = 500 * time.Millisecond

func main() {
	once := flag.Bool("once", false, "sync once and exit (useful for cron)")
	interval := flag.Duration("interval", 30*time.Minute, "sync interval between sweeps")
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

	sync := googleworkspaceoauthsync.New(db, resolverAdapter{base: bootstrap.GoogleOAuthResolver{DB: db}}).
		WithInterval(*interval)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *once {
		listener, listenErr := openWakeListener(ctx, cfg.DatabaseURL)
		if listenErr != nil {
			log.Printf("google-workspace-oauth-sync: -once listener setup failed (manual wake-ups will be dropped): %v", listenErr)
		} else {
			defer listener.Close(context.Background())
		}
		if err := sync.Tick(ctx); err != nil {
			log.Fatalf("google-workspace-oauth-sync: tick failed: %v", err)
		}
		if listener != nil {
			drainWakeNotifications(ctx, listener, sync)
		}
		return
	}
	go runWakeListener(ctx, cfg.DatabaseURL, sync)
	log.Printf("google-workspace-oauth-sync: starting (interval=%s, wake-channel=%s)", *interval, bootstrap.GoogleWorkspaceOAuthSyncWakeChannel)
	if err := sync.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("google-workspace-oauth-sync: %v", err)
	}
}

func runWakeListener(ctx context.Context, dsn string, sync *googleworkspaceoauthsync.Sync) {
	for {
		if err := listenOnce(ctx, dsn, sync); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("google-workspace-oauth-sync: listener failed: %v", err)
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
	if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{bootstrap.GoogleWorkspaceOAuthSyncWakeChannel}.Sanitize()); err != nil {
		_ = conn.Close(context.Background())
		return nil, fmt.Errorf("LISTEN %s: %w", bootstrap.GoogleWorkspaceOAuthSyncWakeChannel, err)
	}
	return conn, nil
}

func listenOnce(ctx context.Context, dsn string, worker *googleworkspaceoauthsync.Sync) error {
	conn, err := openWakeListener(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	return dispatchWakeNotifications(ctx, conn, worker, ctx)
}

func drainWakeNotifications(ctx context.Context, conn *pgx.Conn, worker *googleworkspaceoauthsync.Sync) {
	deadline := time.Now().Add(onceWakeWorkBudget)
	idleSince := time.Now()
	var active atomic.Int64
	for {
		if active.Load() == 0 && !idleSince.IsZero() && time.Since(idleSince) >= onceDrainWindow {
			return
		}
		if time.Now().After(deadline) {
			log.Printf("google-workspace-oauth-sync: -once exiting after %s; some wake-triggered syncs may not have completed", onceWakeWorkBudget)
			return
		}
		waitCtx, stopWaiting := context.WithTimeout(ctx, notificationPollInterval)
		notification, err := conn.WaitForNotification(waitCtx)
		waitErr := waitCtx.Err()
		stopWaiting()
		if err != nil {
			if ctx.Err() != nil {
				log.Printf("google-workspace-oauth-sync: -once interrupted before wake-triggered syncs completed: %v", ctx.Err())
				return
			}
			if waitErr != nil {
				if active.Load() == 0 && idleSince.IsZero() {
					idleSince = time.Now()
				}
				continue
			}
			log.Printf("google-workspace-oauth-sync: -once wake drain failed: %v", err)
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
			if err := worker.WakeIntegration(ctx, id); err != nil {
				log.Printf("google-workspace-oauth-sync: wake integration %s failed: %v", id, err)
			}
		}(integrationID)
	}
}

func dispatchWakeNotifications(listenCtx context.Context, conn *pgx.Conn, worker *googleworkspaceoauthsync.Sync, workCtx context.Context) error {
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
			if err := worker.WakeIntegration(workCtx, id); err != nil {
				log.Printf("google-workspace-oauth-sync: wake integration %s failed: %v", id, err)
			}
		}(integrationID)
	}
}

type resolverAdapter struct {
	base bootstrap.GoogleOAuthResolver
}

func (r resolverAdapter) ResolveGoogleOAuthClient(ctx context.Context, organizationID string) (googleworkspaceoauthsync.OAuthConfig, bool) {
	cfg, ok := r.base.ResolveGoogleOAuthClient(ctx, organizationID)
	if !ok {
		return googleworkspaceoauthsync.OAuthConfig{}, false
	}
	return googleworkspaceoauthsync.OAuthConfig{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret}, true
}
