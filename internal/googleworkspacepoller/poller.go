// Package googleworkspacepoller pulls Google Workspace audit activities from
// the Google Admin Reports API and enqueues them into ingestion_jobs so the
// existing rule evaluators (internal/ingestionworker) can produce findings.
//
// Why a separate package: the ingestion worker is a pure consumer of queued
// jobs. Until this package landed, no producer existed for Google Workspace,
// so connecting Google via OAuth stored a refresh token that nothing ever
// used. The poller closes that gap.
//
// Design notes:
//   - Per integration, per Google application (admin, drive, token, login) we
//     keep a cursor (event time + uniqueQualifier) in google_workspace_sync_cursors.
//     Both fields are required because Google guarantees uniqueness only on the
//     pair, not on time alone.
//   - The first poll for a fresh integration only pulls the most recent 24h.
//     Older history is intentionally skipped to avoid drowning a new tenant in
//     stale findings.
//   - We translate Google's raw event names into the Aperio synthesized event
//     types the worker matches against (EXTERNAL_SHARING_ENABLED, etc). When a
//     Google event does not map cleanly we fall through with the raw uppercase
//     name so future rule additions can match without a poller change.
//   - HTTP failures on a single integration log and update last_error, but do
//     not stop the sweep. One broken tenant should not freeze ingestion for the
//     rest of the fleet.
package googleworkspacepoller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/writer/aperio/internal/runtimeutil"
	"github.com/writer/aperio/internal/syncstate"
	"github.com/writer/aperio/internal/syncwake"
)

const (
	defaultPollInterval = 60 * time.Second
	defaultLookback     = 24 * time.Hour
	tokenURL            = "https://oauth2.googleapis.com/token"
	reportsBaseURL      = "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications"
	// Page size is the per-request item cap accepted by Google's Reports API.
	// We pair it with maxPagesPerApp below as a runaway-fetch safety bound;
	// the cap is on pages, not items, so we never silently drop events past
	// some arbitrary integer N when paginating.
	defaultPageSize = 1000
	// maxPagesPerApp bounds the work per (integration, application, sweep)
	// to roughly 1 000 000 items. A tenant generating more than that within
	// one poll interval is pathological and the operator should investigate;
	// the cursor advance logic in pollApplication still guarantees no
	// permanent data loss in that case (see comments there).
	maxPagesPerApp = 1000
)

// DefaultApplications is the set of Google audit applications the poller
// covers. login is intentionally omitted from the default set because the
// existing worker has no login-specific rules; adding it would only inflate
// ingestion_jobs without producing findings. Add it back once login rules
// land in internal/ingestionworker.
var DefaultApplications = []string{"admin", "drive", "token"}

// OAuthConfig is the credential bundle needed for one token-exchange call.
// The poller resolves a fresh OAuthConfig per integration so per-tenant OAuth
// client rotation in integration_oauth_clients takes effect on the next sweep
// without a process restart.
type OAuthConfig struct {
	ClientID     string
	ClientSecret string
}

// OAuthResolver returns the OAuth client credentials for an organization.
// It is an interface so the bootstrap package's resolver
// (resolveGoogleOAuthConfigForOrg) can be injected without an import cycle.
type OAuthResolver interface {
	ResolveGoogleOAuthClient(ctx context.Context, organizationID string) (OAuthConfig, bool)
}

// Poller is the long-running goroutine that drives Google Workspace ingestion.
// Construct via New and start with Run.
type Poller struct {
	db           *sql.DB
	httpClient   *http.Client
	resolver     OAuthResolver
	interval     time.Duration
	lookback     time.Duration
	applications []string
	nowFn        func() time.Time
	pageSize     int
	maxPages     int
}

// New builds a Poller with sensible defaults. The HTTP client is given a
// 20 second timeout to bound stuck Google requests; tune via Poller.httpClient
// in tests if needed.
func New(db *sql.DB, resolver OAuthResolver) *Poller {
	return &Poller{
		db:           db,
		httpClient:   &http.Client{Timeout: 20 * time.Second},
		resolver:     resolver,
		interval:     defaultPollInterval,
		lookback:     defaultLookback,
		applications: append([]string(nil), DefaultApplications...),
		nowFn:        time.Now,
		pageSize:     defaultPageSize,
		maxPages:     maxPagesPerApp,
	}
}

// WithPageSize overrides the per-request page size. Used in tests to
// exercise pagination with small synthetic pages without spinning up
// thousands of fake activities.
func (p *Poller) WithPageSize(n int) *Poller { p.pageSize = n; return p }

// WithMaxPages overrides the safety bound on per-application pagination.
// Used in tests to exercise the page-cap branch deterministically.
func (p *Poller) WithMaxPages(n int) *Poller { p.maxPages = n; return p }

// WithInterval overrides the poll interval. Useful in tests; production
// callers should accept the default.
func (p *Poller) WithInterval(d time.Duration) *Poller { p.interval = d; return p }

// WithHTTPClient swaps the HTTP client. Used in tests to point at a httptest
// server. The provided client should set its own timeout.
func (p *Poller) WithHTTPClient(c *http.Client) *Poller { p.httpClient = c; return p }

// WithApplications overrides which Google audit applications to poll.
func (p *Poller) WithApplications(apps []string) *Poller {
	p.applications = append([]string(nil), apps...)
	return p
}

// WithNowFn overrides the wall clock; tests inject a deterministic clock so
// cursor and lookback assertions are stable.
func (p *Poller) WithNowFn(fn func() time.Time) *Poller { p.nowFn = fn; return p }

// Run blocks until ctx is cancelled, ticking the poller every interval.
// Each tick is independent: a tick error does not abort the loop, since the
// only durable state lives in google_workspace_sync_cursors and ingestion_jobs.
func (p *Poller) Run(ctx context.Context) error {
	// Run an immediate tick on start so freshly-connected integrations don't
	// have to wait a full interval before any data arrives. Errors are logged
	// but do not stop the loop.
	if err := p.Tick(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("googleworkspacepoller: first tick failed: %v", err)
	}
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := p.Tick(ctx); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("googleworkspacepoller: tick failed: %v", err)
			}
		}
	}
}

// integrationRow is the projection of integration_connections the poller
// needs. Provider is filtered to GOOGLE_WORKSPACE; status is filtered to
// CONNECTED so disconnected integrations do not waste OAuth quota.
type integrationRow struct {
	ID                string
	OrganizationID    string
	ExternalAccountID string
	EncryptedToken    string
}

// Tick performs one sweep across all connected Google Workspace integrations.
// Exported so tests can drive it deterministically without spinning up a
// goroutine + ticker.
func (p *Poller) Tick(ctx context.Context) error {
	integrations, err := p.connectedIntegrations(ctx)
	if err != nil {
		return fmt.Errorf("list integrations: %w", err)
	}
	for _, integ := range integrations {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := p.pollIntegration(ctx, integ); err != nil {
			log.Printf("googleworkspacepoller: integration %s poll failed: %v", integ.ID, err)
		}
	}
	return nil
}

// WakeIntegration runs an out-of-cycle poll for a single integration. The
// poller binary calls this in response to a Postgres NOTIFY (see
// GoogleWorkspaceSyncWakeChannel in internal/bootstrap) so freshly-connected
// integrations land on the connector card with real data immediately,
// instead of waiting up to a full poll interval for the next Tick. Returns
// nil silently if the id does not match a CONNECTED Google Workspace
// integration so stale notifications (e.g. for a since-disconnected row) do
// not surface as errors.
func (p *Poller) WakeIntegration(ctx context.Context, integrationID string) error {
	integrationID, application := syncwake.Decode(integrationID)
	if strings.TrimSpace(integrationID) == "" {
		return nil
	}
	var integ integrationRow
	err := p.db.QueryRowContext(ctx, `
		SELECT id, organization_id, external_account_id, encrypted_access_token
		FROM integration_connections
		WHERE id = $1 AND provider = 'GOOGLE_WORKSPACE' AND status = 'CONNECTED'
	`, integrationID).Scan(&integ.ID, &integ.OrganizationID, &integ.ExternalAccountID, &integ.EncryptedToken)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("load integration %s: %w", integrationID, err)
	}
	if application != "" {
		if !slices.Contains(p.applications, application) {
			return nil
		}
		return p.pollIntegrationApplications(ctx, integ, []string{application}, false)
	}
	return p.pollIntegration(ctx, integ)
}

func (p *Poller) connectedIntegrations(ctx context.Context) ([]integrationRow, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT id, organization_id, external_account_id, encrypted_access_token
		FROM integration_connections
		WHERE provider = 'GOOGLE_WORKSPACE' AND status = 'CONNECTED'
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []integrationRow
	for rows.Next() {
		var r integrationRow
		if err := rows.Scan(&r.ID, &r.OrganizationID, &r.ExternalAccountID, &r.EncryptedToken); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// pollIntegration handles one integration. It resolves the per-org OAuth
// client, exchanges the stored refresh token for a one-shot access token, and
// fans out one HTTP call per application.
func (p *Poller) pollIntegration(ctx context.Context, integ integrationRow) error {
	return p.pollIntegrationApplications(ctx, integ, p.applications, true)
}

func (p *Poller) pollIntegrationApplications(ctx context.Context, integ integrationRow, applications []string, refreshConnector bool) error {
	oauth, ok := p.resolver.ResolveGoogleOAuthClient(ctx, integ.OrganizationID)
	if !ok {
		return errors.New("oauth client unresolved for organization")
	}
	refreshToken, err := runtimeutil.DecryptString(
		integ.EncryptedToken,
		runtimeutil.IntegrationSecretAAD(integ.OrganizationID, "GOOGLE_WORKSPACE", integ.ExternalAccountID, "access_token"),
	)
	if err != nil {
		return fmt.Errorf("decrypt refresh token: %w", err)
	}
	accessToken, err := p.exchangeRefreshToken(ctx, oauth, refreshToken)
	if err != nil {
		return fmt.Errorf("exchange refresh token: %w", err)
	}
	for _, app := range applications {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := p.pollApplication(ctx, integ, app, accessToken); err != nil {
			// Surface to the cursor row so operators can see why a specific
			// application stopped advancing without grepping logs.
			expected, _ := cursorFromPollError(err)
			p.recordError(ctx, integ.ID, app, expected, err)
			log.Printf("googleworkspacepoller: integ=%s app=%s poll failed: %v", integ.ID, app, err)
			continue
		}
	}
	// Best-effort update of integration_connections.last_sync_at so the UI
	// reflects a recent successful sweep even if one application failed.
	if refreshConnector {
		_, _ = p.db.ExecContext(ctx, `UPDATE integration_connections SET last_sync_at = $1, updated_at = NOW() WHERE id = $2`, p.nowFn().UTC(), integ.ID)
	}
	return nil
}

// pollApplication lists activities for one (integration, application) pair
// starting from the persisted cursor (or now-lookback on first poll) and
// enqueues each new activity as one ingestion_jobs row per Google event.
//
// Cursor-advance is delegated to nextCursorAfterSweep so the decision is a
// pure, testable function and the heart-of-correctness comment lives next
// to the code it explains.
func (p *Poller) pollApplication(ctx context.Context, integ integrationRow, application, accessToken string) error {
	cursor, err := p.loadCursor(ctx, integ.ID, application)
	if err != nil {
		return fmt.Errorf("load cursor: %w", err)
	}
	cursorErr := func(err error) error {
		if err == nil {
			return nil
		}
		return cursorPollError{cursor: cursor, err: err}
	}
	startTime := cursor.LastEventTime
	if startTime.IsZero() {
		startTime = p.nowFn().Add(-p.lookback).UTC()
	}
	activities, exhausted, err := p.listActivities(ctx, application, accessToken, startTime, cursor)
	if err != nil {
		return cursorErr(err)
	}
	if len(activities) == 0 {
		p.touchCursor(ctx, integ.ID, application, cursor, cursor.LastEventTime, cursor.LastUniqueQualifier)
		return nil
	}
	// Google returns activities ordered DESC; flip to ASC so the cursor
	// advances monotonically as we iterate and we never re-enqueue when a
	// single call already saw a later event than the cursor.
	for i, j := 0, len(activities)-1; i < j; i, j = i+1, j-1 {
		activities[i], activities[j] = activities[j], activities[i]
	}
	for _, activity := range activities {
		if !cursor.isStrictlyAfter(activity.EventTime, activity.UniqueQualifier) {
			continue
		}
		for _, event := range activity.Events {
			if err := p.enqueueEvent(ctx, integ, application, activity, event); err != nil {
				log.Printf("googleworkspacepoller: enqueue failed integ=%s app=%s id=%s: %v",
					integ.ID, application, activity.UniqueQualifier, err)
				return cursorErr(err)
			}
		}
	}
	if !exhausted {
		log.Printf("googleworkspacepoller: integ=%s app=%s hit page cap (%d pages, %d activities enqueued); leaving cursor untouched so the older un-paged events remain inside future startTime windows. The just-enqueued events will be re-fetched on the next sweep and absorbed as no-op unique-violations by the deterministic ingestion_jobs id.",
			integ.ID, application, p.maxPages, len(activities))
	}
	next := nextCursorAfterSweep(activities, exhausted, cursor)
	p.touchCursor(ctx, integ.ID, application, cursor, next.LastEventTime, next.LastUniqueQualifier)
	return nil
}

// nextCursorAfterSweep returns the cursor value that should be persisted
// after a single (integration, application) sweep. It is a pure function so
// the cursor-advance correctness invariant can be pinned in unit tests
// without touching Postgres.
//
// Correctness rules:
//
//   - len(activities) == 0: nothing new was processed; preserve the
//     persisted cursor verbatim. (touchCursor will still refresh
//     last_polled_at and clear last_error.)
//
//   - exhausted == true: we paginated all the way back to the persisted
//     cursor or ran out of nextPageToken, so there are no unfetched events
//     strictly after the persisted cursor. Safe to advance to the NEWEST
//     processed event (activities[len-1] after the ASC reversal).
//
//   - exhausted == false: page cap was hit. There are still older events
//     in the gap (persisted-cursor, oldest-collected). We MUST NOT advance
//     the cursor in this case. Google's Reports API is a DESC query with
//     startTime as a *lower bound*, so any future call with a larger
//     startTime can never return those older events — they become
//     permanently unreachable. Keeping the persisted cursor unchanged
//     means the next sweep re-fetches the just-enqueued newest events
//     (idempotent: enqueueEvent uses a deterministic ingestion_jobs id
//     and treats unique-violation as a no-op) AND continues paginating
//     into the older range that was cut off by the cap. The tradeoff is
//     extra API calls for a runaway-event tenant, which is the right
//     direction: a tenant that keeps tripping the cap is an ops alert,
//     never a silent data-loss event.
func nextCursorAfterSweep(activities []reportsActivity, exhausted bool, current cursorRow) cursorRow {
	if len(activities) == 0 || !exhausted {
		return current
	}
	newest := activities[len(activities)-1]
	return cursorRow{LastEventTime: newest.EventTime, LastUniqueQualifier: newest.UniqueQualifier}
}

type cursorRow struct {
	LastEventTime       time.Time
	LastUniqueQualifier string
	LastError           string
}

type cursorPollError struct {
	cursor cursorRow
	err    error
}

func (e cursorPollError) Error() string {
	return e.err.Error()
}

func (e cursorPollError) Unwrap() error {
	return e.err
}

func cursorFromPollError(err error) (cursorRow, bool) {
	var pollErr cursorPollError
	if errors.As(err, &pollErr) {
		return pollErr.cursor, true
	}
	return cursorRow{}, false
}

func (c cursorRow) isStrictlyAfter(t time.Time, qualifier string) bool {
	if c.LastEventTime.IsZero() {
		return true
	}
	if t.After(c.LastEventTime) {
		return true
	}
	if t.Equal(c.LastEventTime) && qualifier > c.LastUniqueQualifier {
		return true
	}
	return false
}

func (p *Poller) loadCursor(ctx context.Context, integrationID, application string) (cursorRow, error) {
	var c cursorRow
	var lastErr sql.NullString
	err := p.db.QueryRowContext(ctx, `
		SELECT last_event_time, last_unique_qualifier, last_error
		FROM google_workspace_sync_cursors
		WHERE integration_id = $1 AND application = $2
	`, integrationID, application).Scan(&c.LastEventTime, &c.LastUniqueQualifier, &lastErr)
	if errors.Is(err, sql.ErrNoRows) {
		return cursorRow{}, nil
	}
	c.LastError = lastErr.String
	return c, err
}

func (p *Poller) touchCursor(ctx context.Context, integrationID, application string, expected cursorRow, eventTime time.Time, qualifier string) {
	// We always upsert: on first poll the cursor row doesn't exist yet, on
	// subsequent polls it must advance even when no new activities arrived
	// (so last_polled_at moves forward and last_error clears).
	if eventTime.IsZero() {
		eventTime = p.nowFn().Add(-p.lookback).UTC()
	}
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO google_workspace_sync_cursors
			(integration_id, application, last_event_time, last_unique_qualifier, last_polled_at, last_error)
		VALUES ($1, $2, $3, $4, $5, NULL)
		ON CONFLICT (integration_id, application) DO UPDATE SET
			last_event_time = EXCLUDED.last_event_time,
			last_unique_qualifier = EXCLUDED.last_unique_qualifier,
			last_polled_at = EXCLUDED.last_polled_at,
			last_error = NULL
		WHERE COALESCE(google_workspace_sync_cursors.last_error, '') NOT LIKE $6
		   OR (
				google_workspace_sync_cursors.last_event_time = $7
				AND google_workspace_sync_cursors.last_unique_qualifier = $8
		   )
	`, integrationID, application, eventTime, qualifier, p.nowFn().UTC(), syncstate.BackfillQueuedPrefix+"%", expected.LastEventTime, expected.LastUniqueQualifier)
	if err != nil {
		log.Printf("googleworkspacepoller: touchCursor failed integ=%s app=%s: %v", integrationID, application, err)
	}
}

func (p *Poller) recordError(ctx context.Context, integrationID, application string, expected cursorRow, pollErr error) {
	msg := pollErr.Error()
	if len(msg) > 480 {
		msg = msg[:480]
	}
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO google_workspace_sync_cursors
			(integration_id, application, last_event_time, last_unique_qualifier, last_polled_at, last_error)
		VALUES ($1, $2, $3, '', $4, $5)
		ON CONFLICT (integration_id, application) DO UPDATE SET
			last_polled_at = EXCLUDED.last_polled_at,
			last_error = EXCLUDED.last_error
		WHERE COALESCE(google_workspace_sync_cursors.last_error, '') NOT LIKE $6
		   OR (
				google_workspace_sync_cursors.last_event_time = $7
				AND google_workspace_sync_cursors.last_unique_qualifier = $8
		   )
	`, integrationID, application, p.nowFn().Add(-p.lookback).UTC(), p.nowFn().UTC(), msg, syncstate.BackfillQueuedPrefix+"%", expected.LastEventTime, expected.LastUniqueQualifier)
	if err != nil {
		log.Printf("googleworkspacepoller: recordError failed integ=%s app=%s: %v", integrationID, application, err)
	}
}

// enqueueEvent inserts one ingestion_jobs row per Google event. The event
// type is normalized into the synthesized Aperio constants the existing
// worker matches against, so EXTERNAL_SHARING_ENABLED / SUPER_ADMIN_GRANTED /
// etc work end-to-end without changes to internal/ingestionworker.
//
// ownerDomain is computed once per event (not derived later) so the same
// value drives both the EXTERNAL_SHARING_ENABLED classifier and the payload
// the worker reads. Resolution order, most authoritative first:
//  1. parameters.owner (the doc owner email reported by Drive)
//  2. the activity actor's email domain
//  3. the integration's external_account_id (set in the OAuth callback to
//     the verified Google Workspace hosted domain)
//
// If all three are empty the classifier stays conservative and refuses to
// fire on target-email or target-domain signals.
func (p *Poller) enqueueEvent(ctx context.Context, integ integrationRow, application string, activity reportsActivity, event reportsEvent) error {
	return enqueueGoogleWorkspaceEvent(ctx, p.db, integ, application, activity, event)
}

func enqueueGoogleWorkspaceEvent(ctx context.Context, db *sql.DB, integ integrationRow, application string, activity reportsActivity, event reportsEvent) error {
	return enqueueGoogleWorkspaceEventWithSource(ctx, db, integ, application, googleReportsQueueSource(application), activity, event)
}

func enqueueGoogleWorkspaceEventWithSource(ctx context.Context, db *sql.DB, integ integrationRow, application, source string, activity reportsActivity, event reportsEvent) error {
	ownerDomain := resolveOwnerDomain(integ, activity, event.Parameters)
	mapped := MapEventType(application, event.Name, event.Parameters, ownerDomain)
	if mapped == "" {
		// No rule evaluator exists for this raw Google event, so enqueueing
		// would only produce DEAD_LETTER noise after retry exhaustion. Drop
		// silently; if we ever add an evaluator for this event name, the
		// mapping above will start returning a non-empty type and the poller
		// will begin enqueueing without any other change.
		return nil
	}
	payload := buildJobPayload(application, activity, event, ownerDomain)
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	legacyID := googleWorkspaceLegacyJobID(activity, event)
	err = insertGoogleWorkspaceIngestionJob(ctx, db, legacyID, integ, mapped, source, activity, payloadJSON)
	if err == nil {
		return nil
	}
	if !isUniqueViolation(err) {
		return err
	}
	matchesExisting, lookupErr := googleWorkspaceLegacyJobMatches(ctx, db, legacyID, integ, mapped, source, activity)
	if lookupErr != nil {
		return lookupErr
	}
	if matchesExisting {
		// Cursor lagged behind a prior enqueue (retry or overlap); skipping
		// keeps the worker queue idempotent and preserves pre-scoped job IDs.
		return nil
	}
	err = insertGoogleWorkspaceIngestionJob(ctx, db, googleWorkspaceScopedJobID(integ, source, application, activity, event), integ, mapped, source, activity, payloadJSON)
	if err != nil && isUniqueViolation(err) {
		return nil
	}
	return err
}

func googleReportsQueueSource(application string) string {
	return "google.reports." + application
}

func googleBigQueryQueueSource(recordType string) string {
	return "google.bigquery." + recordType
}

func insertGoogleWorkspaceIngestionJob(ctx context.Context, db *sql.DB, id string, integ integrationRow, mapped, source string, activity reportsActivity, payloadJSON []byte) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO ingestion_jobs (
			id, organization_id, integration_id, provider, event_type, source, actor,
			occurred_at, payload, status, attempts, max_attempts, next_attempt_at, created_at, updated_at
		)
		VALUES ($1, $2, $3, 'GOOGLE_WORKSPACE', $4, $5, $6, $7, $8::jsonb, 'QUEUED', 0, 3, NOW(), NOW(), NOW())
	`,
		id,
		integ.OrganizationID,
		integ.ID,
		mapped,
		source,
		activity.Actor.Email,
		activity.EventTime,
		payloadJSON,
	)
	return err
}

func googleWorkspaceLegacyJobMatches(ctx context.Context, db *sql.DB, id string, integ integrationRow, mapped, source string, activity reportsActivity) (bool, error) {
	var existingOrg, existingIntegration, existingEventType, existingSource, existingSourceEventID string
	err := db.QueryRowContext(ctx, `
		SELECT organization_id, integration_id, event_type, source, payload->>'sourceEventId'
		FROM ingestion_jobs
		WHERE id = $1
	`, id).Scan(&existingOrg, &existingIntegration, &existingEventType, &existingSource, &existingSourceEventID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return existingOrg == integ.OrganizationID &&
		existingIntegration == integ.ID &&
		existingEventType == mapped &&
		existingSource == source &&
		existingSourceEventID == activity.UniqueQualifier, nil
}

func googleWorkspaceLegacyJobID(activity reportsActivity, event reportsEvent) string {
	return "ijb_" + activity.UniqueQualifier + "_" + event.Name
}

func googleWorkspaceScopedJobID(integ integrationRow, source, application string, activity reportsActivity, event reportsEvent) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		integ.OrganizationID,
		integ.ID,
		source,
		application,
		activity.UniqueQualifier,
		event.Name,
	}, "\x00")))
	return "ijb_gws_" + hex.EncodeToString(sum[:])
}

// buildJobPayload flattens Google's array-based parameters into the
// map[string]any shape the existing rule evaluators expect (they call
// nestedString(payload, "parameters", "doc_title") and similar).
func buildJobPayload(application string, activity reportsActivity, event reportsEvent, ownerDomain string) map[string]any {
	parameters := map[string]any{}
	for _, param := range event.Parameters {
		if param.MultiValue != nil {
			parameters[param.Name] = param.MultiValue
			continue
		}
		if param.IntValue != "" {
			parameters[param.Name] = param.IntValue
			continue
		}
		if param.BoolValue != nil {
			parameters[param.Name] = *param.BoolValue
			continue
		}
		parameters[param.Name] = param.Value
	}
	payload := map[string]any{
		"application":   application,
		"parameters":    parameters,
		"sourceEventId": activity.UniqueQualifier,
		"ownerDomain":   ownerDomain,
	}
	if name, ok := parameters["doc_title"].(string); ok && name != "" {
		payload["resource"] = map[string]any{"name": name, "id": stringParam(parameters, "doc_id")}
	}
	if email := stringParam(parameters, "USER_EMAIL"); email != "" {
		payload["target"] = map[string]any{"email": email}
	} else if email := stringParam(parameters, "user_email"); email != "" {
		payload["target"] = map[string]any{"email": email}
	}
	return payload
}

func stringParam(parameters map[string]any, key string) string {
	if v, ok := parameters[key].(string); ok {
		return v
	}
	return ""
}

// resolveOwnerDomain picks the most authoritative source of the workspace's
// own domain for a single event. The order matters: parameters.owner is the
// actual document owner (most specific for Drive sharing); the activity
// actor is the next best because they had to be inside the tenant to make
// the call; and integ.ExternalAccountID is the verified hosted domain
// captured at OAuth time as the last-resort tenant-wide default.
func resolveOwnerDomain(integ integrationRow, activity reportsActivity, parameters []reportsParameter) string {
	for _, param := range parameters {
		if strings.EqualFold(param.Name, "owner") && param.Value != "" {
			if domain := domainFromEmail(param.Value); domain != "" {
				return domain
			}
		}
	}
	if domain := domainFromEmail(activity.Actor.Email); domain != "" {
		return domain
	}
	return strings.ToLower(strings.TrimSpace(integ.ExternalAccountID))
}

func domainFromEmail(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		// A bare domain (no @) is a valid owner value in some Drive events.
		// Treat it as the domain itself.
		if at < 0 && strings.Contains(email, ".") {
			return strings.ToLower(strings.TrimSpace(email))
		}
		return ""
	}
	return strings.ToLower(strings.TrimSpace(email[at+1:]))
}

// reportsActivity mirrors the subset of Google's Activity resource we use.
// We intentionally don't model every field — only what the rule evaluators
// read — so future Reports API additions can pass through untouched.
type reportsActivity struct {
	EventTime       time.Time
	UniqueQualifier string
	Actor           reportsActor
	Events          []reportsEvent
}

type reportsActor struct {
	Email      string `json:"email"`
	ProfileID  string `json:"profileId"`
	CallerType string `json:"callerType"`
}

type reportsEvent struct {
	Type       string             `json:"type"`
	Name       string             `json:"name"`
	Parameters []reportsParameter `json:"parameters"`
}

type reportsParameter struct {
	Name       string   `json:"name"`
	Value      string   `json:"value,omitempty"`
	IntValue   string   `json:"intValue,omitempty"`
	BoolValue  *bool    `json:"boolValue,omitempty"`
	MultiValue []string `json:"multiValue,omitempty"`
}

type reportsResponse struct {
	Items []struct {
		ID struct {
			Time            time.Time `json:"time"`
			UniqueQualifier string    `json:"uniqueQualifier"`
			ApplicationName string    `json:"applicationName"`
			CustomerID      string    `json:"customerId"`
		} `json:"id"`
		Actor  reportsActor   `json:"actor"`
		Events []reportsEvent `json:"events"`
	} `json:"items"`
	NextPageToken string `json:"nextPageToken,omitempty"`
}

// listActivities paginates the Reports API until one of three terminators
// fires:
//
//  1. A returned item is at-or-before the persisted cursor. Because Google
//     returns items DESC, every subsequent item is also at-or-before, so we
//     stop early without burning additional pages.
//  2. The response has no nextPageToken. There is nothing more on the server
//     side that matches the startTime filter.
//  3. We hit maxPages. This bounds runaway fetches for pathological tenants.
//
// The boolean return value distinguishes terminator (1) and (2) — both mean
// "fully drained" — from terminator (3), which means "older events may
// remain on Google". The caller (pollApplication) uses that signal to decide
// whether to advance the cursor to the NEWEST processed event (safe) or the
// OLDEST processed event (the recovery case, where the next sweep will
// re-fetch what we just enqueued AND continue into the unfetched older
// range; the enqueue is idempotent via the deterministic ingestion_jobs id).
//
// Items returned by this function are STRICTLY AFTER the cursor — the
// cursor-comparison filter inside the loop is what makes the strict-after
// guarantee hold across the time/uniqueQualifier tiebreaker.
func (p *Poller) listActivities(ctx context.Context, application, accessToken string, startTime time.Time, cursor cursorRow) ([]reportsActivity, bool, error) {
	endpoint := reportsBaseURL + "/" + url.PathEscape(application)
	collected := make([]reportsActivity, 0, p.pageSize)
	pageToken := ""
	pageSize := p.pageSize
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	for page := 0; page < p.maxPages; page++ {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		q := url.Values{}
		q.Set("startTime", startTime.UTC().Format(time.RFC3339))
		q.Set("maxResults", strconvI(pageSize))
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+q.Encode(), nil)
		if err != nil {
			return nil, false, err
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Accept", "application/json")
		resp, err := p.httpClient.Do(req)
		if err != nil {
			return nil, false, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		_ = resp.Body.Close()
		if err != nil {
			return nil, false, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			snippet := string(body)
			if len(snippet) > 200 {
				snippet = snippet[:200]
			}
			return nil, false, fmt.Errorf("google reports api %d: %s", resp.StatusCode, snippet)
		}
		var decoded reportsResponse
		if err := json.Unmarshal(body, &decoded); err != nil {
			return nil, false, fmt.Errorf("decode reports response: %w", err)
		}
		reachedCursor := false
		for _, item := range decoded.Items {
			activity := reportsActivity{
				EventTime:       item.ID.Time.UTC(),
				UniqueQualifier: item.ID.UniqueQualifier,
				Actor:           item.Actor,
				Events:          item.Events,
			}
			if !cursor.isStrictlyAfter(activity.EventTime, activity.UniqueQualifier) {
				reachedCursor = true
				break
			}
			collected = append(collected, activity)
		}
		if reachedCursor || decoded.NextPageToken == "" {
			return collected, true, nil
		}
		pageToken = decoded.NextPageToken
	}
	// Page cap hit; caller treats !exhausted as the recovery case.
	return collected, false, nil
}

// strconvI is a tiny shim so the import block stays free of strconv just
// for one int-to-string conversion. Performance-irrelevant on this path.
func strconvI(n int) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = digits[n%10]
		n /= 10
	}
	if negative {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// exchangeRefreshToken converts the stored Google refresh token into a
// short-lived access token. We intentionally do NOT persist the access
// token; Google's refresh tokens are durable and re-exchange is cheap.
func (p *Poller) exchangeRefreshToken(ctx context.Context, oauth OAuthConfig, refreshToken string) (string, error) {
	form := url.Values{}
	form.Set("client_id", oauth.ClientID)
	form.Set("client_secret", oauth.ClientSecret)
	form.Set("refresh_token", refreshToken)
	form.Set("grant_type", "refresh_token")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := string(body)
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		return "", fmt.Errorf("token exchange %d: %s", resp.StatusCode, snippet)
	}
	var decoded struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", err
	}
	if decoded.AccessToken == "" {
		return "", errors.New("token exchange response missing access_token")
	}
	return decoded.AccessToken, nil
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "23505") || strings.Contains(msg, "duplicate key")
}
