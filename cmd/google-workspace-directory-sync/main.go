// google-workspace-directory-sync pulls the Google Workspace user directory
// into saas_identities so the Security Graph, the executive report, and the
// Google Workspace assessment stop reporting 0 privileged identities / 0
// active accounts / 0% MFA coverage on real tenants. Until this command
// landed, the only producer of saas_identities was scripts/seed.ts (demo
// data); the live tables stayed empty after a Google connect even though
// the audit-log poller was already producing findings.
//
// Separated from cmd/google-workspace-poller because the two read different
// Google APIs (admin.reports vs admin.directory), have different rate
// limits, and progress on very different cadences. Coupling them would
// force the audit pipeline to wait through a Directory API outage.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/writer/aperio/internal/bootstrap"
	"github.com/writer/aperio/internal/config"
	"github.com/writer/aperio/internal/googleworkspacedirectorysync"
	"github.com/writer/aperio/internal/syncwake"
)

const onceDrainWindow = 2 * time.Second
const onceWakeWorkBudget = 60 * time.Second
const notificationPollInterval = 500 * time.Millisecond

func main() {
	once := flag.Bool("once", false, "sync once and exit (useful for cron)")
	interval := flag.Duration("interval", 15*time.Minute, "sync interval between sweeps")
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

	sync := googleworkspacedirectorysync.New(db, resolverAdapter{base: bootstrap.GoogleOAuthResolver{DB: db}}).
		WithInterval(*interval)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *once {
		listener, listenErr := openWakeListener(ctx, cfg.DatabaseURL)
		if listenErr != nil {
			log.Printf("google-workspace-directory-sync: -once listener setup failed (manual wake-ups will be dropped): %v", listenErr)
		} else {
			defer listener.Close(context.Background())
		}
		if err := sync.Tick(ctx); err != nil {
			log.Fatalf("google-workspace-directory-sync: tick failed: %v", err)
		}
		if listener != nil {
			drainWakeNotifications(ctx, listener, sync, db)
		}
		return
	}
	go runWakeListener(ctx, cfg.DatabaseURL, sync, db)
	log.Printf("google-workspace-directory-sync: starting (interval=%s, wake-channel=%s)", *interval, bootstrap.GoogleWorkspaceDirectorySyncWakeChannel)
	if err := sync.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("google-workspace-directory-sync: %v", err)
	}
}

func runWakeListener(ctx context.Context, dsn string, sync *googleworkspacedirectorysync.Sync, notifyDB *sql.DB) {
	for {
		if err := listenOnce(ctx, dsn, sync, notifyDB); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("google-workspace-directory-sync: listener failed: %v", err)
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
	if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{bootstrap.GoogleWorkspaceDirectorySyncWakeChannel}.Sanitize()); err != nil {
		_ = conn.Close(context.Background())
		return nil, fmt.Errorf("LISTEN %s: %w", bootstrap.GoogleWorkspaceDirectorySyncWakeChannel, err)
	}
	return conn, nil
}

func listenOnce(ctx context.Context, dsn string, worker *googleworkspacedirectorysync.Sync, notifyDB *sql.DB) error {
	conn, err := openWakeListener(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	return dispatchWakeNotifications(ctx, conn, worker, notifyDB, ctx)
}

func drainWakeNotifications(ctx context.Context, conn *pgx.Conn, worker *googleworkspacedirectorysync.Sync, notifyDB *sql.DB) {
	deadline := time.Now().Add(onceWakeWorkBudget)
	idleSince := time.Now()
	var active atomic.Int64
	for {
		if active.Load() == 0 && !idleSince.IsZero() && time.Since(idleSince) >= onceDrainWindow {
			return
		}
		if time.Now().After(deadline) {
			log.Printf("google-workspace-directory-sync: -once exiting after %s; some wake-triggered syncs may not have completed", onceWakeWorkBudget)
			return
		}
		waitCtx, stopWaiting := context.WithTimeout(ctx, notificationPollInterval)
		notification, err := conn.WaitForNotification(waitCtx)
		waitErr := waitCtx.Err()
		stopWaiting()
		if err != nil {
			if ctx.Err() != nil {
				log.Printf("google-workspace-directory-sync: -once interrupted before wake-triggered syncs completed: %v", ctx.Err())
				return
			}
			if waitErr != nil {
				if active.Load() == 0 && idleSince.IsZero() {
					idleSince = time.Now()
				}
				continue
			}
			log.Printf("google-workspace-directory-sync: -once wake drain failed: %v", err)
			return
		}
		integrationID, mode := syncwake.Decode(notification.Payload)
		if integrationID == "" {
			continue
		}
		active.Add(1)
		idleSince = time.Time{}
		go func(id, mode string) {
			defer active.Add(-1)
			handleDirectoryWake(ctx, worker, notifyDB, id, mode)
		}(integrationID, mode)
	}
}

func dispatchWakeNotifications(listenCtx context.Context, conn *pgx.Conn, worker *googleworkspacedirectorysync.Sync, notifyDB *sql.DB, workCtx context.Context) error {
	for {
		notification, err := conn.WaitForNotification(listenCtx)
		if err != nil {
			if listenCtx.Err() != nil {
				return nil
			}
			return err
		}
		integrationID, mode := syncwake.Decode(notification.Payload)
		if integrationID == "" {
			continue
		}
		go handleDirectoryWake(workCtx, worker, notifyDB, integrationID, mode)
	}
}

func handleDirectoryWake(ctx context.Context, worker *googleworkspacedirectorysync.Sync, notifyDB *sql.DB, integrationID, mode string) {
	if err := worker.WakeIntegration(ctx, integrationID); err != nil {
		log.Printf("google-workspace-directory-sync: wake integration %s failed: %v", integrationID, err)
		return
	}
	if mode == "" {
		return
	}
	if mode != syncwake.ModeOAuthAfterDirectorySync {
		log.Printf("google-workspace-directory-sync: wake integration %s ignored unsupported mode %q", integrationID, mode)
		return
	}
	if err := notifyOAuthAfterDirectorySync(ctx, notifyDB, integrationID); err != nil {
		log.Printf("google-workspace-directory-sync: wake integration %s could not notify oauth sync: %v", integrationID, err)
	}
}

func notifyOAuthAfterDirectorySync(ctx context.Context, db *sql.DB, integrationID string) error {
	if _, err := db.ExecContext(ctx, `SELECT pg_notify($1, $2)`, bootstrap.GoogleWorkspaceOAuthSyncWakeChannel, integrationID); err != nil {
		return err
	}
	log.Printf("google-workspace-directory-sync: integration %s refreshed directory; notified %s", integrationID, bootstrap.GoogleWorkspaceOAuthSyncWakeChannel)
	return nil
}

// resolverAdapter bridges bootstrap's local OAuthConfig type with the
// directory sync's OAuthConfig. They are structurally identical.
type resolverAdapter struct {
	base bootstrap.GoogleOAuthResolver
}

func (r resolverAdapter) ResolveGoogleOAuthClient(ctx context.Context, organizationID string) (googleworkspacedirectorysync.OAuthConfig, bool) {
	cfg, ok := r.base.ResolveGoogleOAuthClient(ctx, organizationID)
	if !ok {
		return googleworkspacedirectorysync.OAuthConfig{}, false
	}
	return googleworkspacedirectorysync.OAuthConfig{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret}, true
}
