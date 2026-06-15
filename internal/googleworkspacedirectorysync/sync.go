// Package googleworkspacedirectorysync pulls the Google Workspace user
// directory and upserts it into saas_identities. Until this package landed,
// no production producer wrote to saas_identities for ANY provider —
// Security Graph and the executive report sourced their identity / MFA /
// privileged-account counts from a table that only the demo seed populated,
// so live tenants always saw zero. This sync closes that gap for Google.
//
// Why a separate binary from the audit-log poller: the two read different
// Google APIs (admin.reports vs admin.directory), have different rate limits,
// and progress on very different cadences — audit-logs are minute-fresh and
// drive findings; the directory typically only shifts when employees join,
// leave, or get promoted. Running them in the same loop would force them to
// share an interval and would couple a Directory API outage to the audit
// pipeline's recovery latency.
//
// Design notes:
//   - The Directory API has no streaming "since" filter; the sync does a
//     full users.list page-walk on every tick. For a typical workspace
//     (low thousands of users) that completes in seconds.
//   - Pagination uses nextPageToken; maxPagesPerTick bounds runaway fetches
//     the same way the audit poller's maxPagesPerApp does.
//   - HTTP failures on a single integration update last_error and continue
//     to the next integration; one broken tenant must not freeze the fleet.
//   - The saas_identities upsert is keyed on (organization_id, provider,
//     external_id) — Google's stable user id — so renames, email changes,
//     and re-provisioning all converge on the same row.
package googleworkspacedirectorysync

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/writer/aperio/internal/runtimeutil"
)

const (
	defaultSyncInterval = 15 * time.Minute
	tokenURL            = "https://oauth2.googleapis.com/token"
	directoryUsersURL   = "https://admin.googleapis.com/admin/directory/v1/users"
	defaultPageSize     = 200
	maxPagesPerTick     = 200 // bounds at ~40k users per integration per tick
)

// OAuthConfig and OAuthResolver mirror the audit poller's signatures so
// the bootstrap-side resolver can be reused without an import cycle.
type OAuthConfig struct {
	ClientID     string
	ClientSecret string
}

type OAuthResolver interface {
	ResolveGoogleOAuthClient(ctx context.Context, organizationID string) (OAuthConfig, bool)
}

// Sync is the long-running goroutine that drives directory ingestion.
type Sync struct {
	db         *sql.DB
	httpClient *http.Client
	resolver   OAuthResolver
	interval   time.Duration
	nowFn      func() time.Time
	pageSize   int
	maxPages   int
}

func New(db *sql.DB, resolver OAuthResolver) *Sync {
	return &Sync{
		db:         db,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		resolver:   resolver,
		interval:   defaultSyncInterval,
		nowFn:      time.Now,
		pageSize:   defaultPageSize,
		maxPages:   maxPagesPerTick,
	}
}

func (s *Sync) WithInterval(d time.Duration) *Sync  { s.interval = d; return s }
func (s *Sync) WithHTTPClient(c *http.Client) *Sync { s.httpClient = c; return s }
func (s *Sync) WithNowFn(fn func() time.Time) *Sync { s.nowFn = fn; return s }
func (s *Sync) WithPageSize(n int) *Sync            { s.pageSize = n; return s }
func (s *Sync) WithMaxPages(n int) *Sync            { s.maxPages = n; return s }

// Run blocks until ctx is cancelled, ticking every interval. The first
// tick fires immediately so a freshly-connected integration does not have
// to wait a full interval before users appear in saas_identities.
func (s *Sync) Run(ctx context.Context) error {
	if err := s.Tick(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("googleworkspacedirectorysync: first tick failed: %v", err)
	}
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := s.Tick(ctx); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("googleworkspacedirectorysync: tick failed: %v", err)
			}
		}
	}
}

type integrationRow struct {
	ID                string
	OrganizationID    string
	ExternalAccountID string
	EncryptedToken    string
}

// Tick performs one sweep across all connected Google Workspace integrations.
func (s *Sync) Tick(ctx context.Context) error {
	integrations, err := s.connectedIntegrations(ctx)
	if err != nil {
		return fmt.Errorf("list integrations: %w", err)
	}
	for _, integ := range integrations {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := s.syncIntegration(ctx, integ); err != nil {
			s.recordError(ctx, integ.ID, err)
			log.Printf("googleworkspacedirectorysync: integ=%s sync failed: %v", integ.ID, err)
			continue
		}
	}
	return nil
}

func (s *Sync) WakeIntegration(ctx context.Context, integrationID string) error {
	integ, err := s.connectedIntegration(ctx, integrationID)
	if err != nil {
		return err
	}
	if err := s.syncIntegration(ctx, integ); err != nil {
		s.recordError(ctx, integ.ID, err)
		return err
	}
	return nil
}

func (s *Sync) connectedIntegrations(ctx context.Context) ([]integrationRow, error) {
	rows, err := s.db.QueryContext(ctx, `
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

func (s *Sync) connectedIntegration(ctx context.Context, integrationID string) (integrationRow, error) {
	var r integrationRow
	err := s.db.QueryRowContext(ctx, `
		SELECT id, organization_id, external_account_id, encrypted_access_token
		FROM integration_connections
		WHERE id = $1 AND provider = 'GOOGLE_WORKSPACE' AND status = 'CONNECTED'
	`, strings.TrimSpace(integrationID)).Scan(&r.ID, &r.OrganizationID, &r.ExternalAccountID, &r.EncryptedToken)
	if errors.Is(err, sql.ErrNoRows) {
		return integrationRow{}, fmt.Errorf("integration not found")
	}
	return r, err
}

// syncIntegration handles one integration end-to-end: token exchange, full
// page-walk of users.list, upsert per user, cursor update.
func (s *Sync) syncIntegration(ctx context.Context, integ integrationRow) error {
	oauth, ok := s.resolver.ResolveGoogleOAuthClient(ctx, integ.OrganizationID)
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
	accessToken, err := s.exchangeRefreshToken(ctx, oauth, refreshToken)
	if err != nil {
		return fmt.Errorf("exchange refresh token: %w", err)
	}
	users, listErr := s.listUsers(ctx, accessToken)
	tenantDomain := strings.ToLower(strings.TrimSpace(integ.ExternalAccountID))
	now := s.nowFn().UTC()
	for _, u := range users {
		if err := s.upsertIdentity(ctx, integ, mapIdentity(u, tenantDomain, now), now); err != nil {
			// One bad row should not abort the whole sweep; surface to the
			// cursor's last_error so operators can investigate.
			return fmt.Errorf("upsert identity %s: %w", u.ID, err)
		}
	}
	if listErr != nil {
		return fmt.Errorf("list users: %w", listErr)
	}
	s.touchCursor(ctx, integ.ID, len(users))
	_, _ = s.db.ExecContext(ctx, `UPDATE integration_connections SET last_sync_at = $1, updated_at = NOW() WHERE id = $2`, now, integ.ID)
	return nil
}

// listUsers paginates the Directory API users endpoint with customer=my_customer
// (Google's special string meaning "the customer this access token belongs to")
// and projection=full so the isAdmin / isEnforcedIn2Sv / isEnrolledIn2Sv
// fields the mapper reads are populated.
func (s *Sync) listUsers(ctx context.Context, accessToken string) ([]googleUser, error) {
	pageSize := s.pageSize
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	maxPages := s.maxPages
	if maxPages <= 0 {
		maxPages = maxPagesPerTick
	}
	collected := make([]googleUser, 0, pageSize)
	pageToken := ""
	for page := 0; page < maxPages; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		q := url.Values{}
		q.Set("customer", "my_customer")
		q.Set("maxResults", itoa(pageSize))
		q.Set("projection", "full")
		q.Set("orderBy", "email")
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, directoryUsersURL+"?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Accept", "application/json")
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			snippet := string(body)
			if len(snippet) > 200 {
				snippet = snippet[:200]
			}
			return nil, fmt.Errorf("google directory api %d: %s", resp.StatusCode, snippet)
		}
		var decoded googleUsersResponse
		if err := json.Unmarshal(body, &decoded); err != nil {
			return nil, fmt.Errorf("decode directory response: %w", err)
		}
		collected = append(collected, decoded.Users...)
		if decoded.NextPageToken == "" {
			return collected, nil
		}
		pageToken = decoded.NextPageToken
	}
	return collected, fmt.Errorf("directory users page cap reached after %d pages (%d users); next page token still present", maxPages, len(collected))
}

// upsertIdentity writes one saas_identities row. We let Postgres generate
// the id on first INSERT (matching Prisma's @default(cuid()) behavior) and
// rely on the (organization_id, provider, external_id) unique to converge
// on update.
func (s *Sync) upsertIdentity(ctx context.Context, integ integrationRow, m mappedIdentity, now time.Time) error {
	if strings.TrimSpace(m.ExternalID) == "" {
		// Google must always return id; defend anyway so a malformed
		// directory page does not pollute saas_identities with empty keys.
		return nil
	}
	id := "ide_" + integ.ID + "_" + m.ExternalID
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO saas_identities (
			id, organization_id, integration_id, provider, external_id, email, display_name,
			kind, status, role, mfa_enabled, is_privileged, is_external,
			last_observed_at, risk_score, created_at, updated_at
		) VALUES ($1, $2, $3, 'GOOGLE_WORKSPACE'::"SaaSProvider", $4, $5, $6,
			'USER'::"SaasIdentityKind", $7::"SaasIdentityStatus", $8, $9, $10, $11,
			$12, 0, NOW(), NOW())
		ON CONFLICT (organization_id, provider, external_id) DO UPDATE SET
			integration_id    = EXCLUDED.integration_id,
			email             = EXCLUDED.email,
			display_name      = EXCLUDED.display_name,
			status            = EXCLUDED.status,
			role              = EXCLUDED.role,
			mfa_enabled       = EXCLUDED.mfa_enabled,
			is_privileged     = EXCLUDED.is_privileged,
			is_external       = EXCLUDED.is_external,
			last_observed_at  = EXCLUDED.last_observed_at,
			updated_at        = NOW()
	`,
		id, integ.OrganizationID, integ.ID, m.ExternalID, nullableString(m.Email),
		nullableString(m.DisplayName), m.Status, nullableString(m.Role),
		nullableBool(m.MfaEnabled), m.IsPrivileged, m.IsExternal, now,
	)
	return err
}

func (s *Sync) touchCursor(ctx context.Context, integrationID string, userCount int) {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO google_workspace_directory_sync_cursors
			(integration_id, last_synced_at, last_user_count, last_error)
		VALUES ($1, $2, $3, NULL)
		ON CONFLICT (integration_id) DO UPDATE SET
			last_synced_at  = EXCLUDED.last_synced_at,
			last_user_count = EXCLUDED.last_user_count,
			last_error      = NULL
	`, integrationID, s.nowFn().UTC(), userCount)
	if err != nil {
		log.Printf("googleworkspacedirectorysync: touchCursor failed integ=%s: %v", integrationID, err)
	}
}

func (s *Sync) recordError(ctx context.Context, integrationID string, syncErr error) {
	msg := syncErr.Error()
	if len(msg) > 480 {
		msg = msg[:480]
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO google_workspace_directory_sync_cursors
			(integration_id, last_synced_at, last_user_count, last_error)
		VALUES ($1, $2, 0, $3)
		ON CONFLICT (integration_id) DO UPDATE SET
			last_error = EXCLUDED.last_error
	`, integrationID, s.nowFn().UTC(), msg)
	if err != nil {
		log.Printf("googleworkspacedirectorysync: recordError failed integ=%s: %v", integrationID, err)
	}
}

// exchangeRefreshToken converts the stored Google refresh token into a
// short-lived access token. Duplicated from the audit poller rather than
// extracted into a shared package because the two packages must not import
// each other (avoid future cycles) and the function is tiny.
func (s *Sync) exchangeRefreshToken(ctx context.Context, oauth OAuthConfig, refreshToken string) (string, error) {
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
	resp, err := s.httpClient.Do(req)
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

func itoa(n int) string {
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

func nullableString(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}

func nullableBool(v *bool) any {
	if v == nil {
		return nil
	}
	return *v
}
