// Package googleworkspaceoauthsync pulls Google Workspace per-user OAuth
// grants and upserts them into security_assets (type=OAUTH_APP, labels
// including 'shadow-it') and oauth_app_grants. Until this package landed,
// no production producer wrote to either table for Google, so the
// Shadow IT page showed zero OAuth apps for live tenants even after a
// successful Google connect.
//
// Design notes:
//   - Google's Directory API exposes user-granted OAuth tokens via
//     admin.users.tokens.list, which is per-user. The sync walks all
//     known saas_identities for the integration (populated by
//     googleworkspacedirectorysync) and calls tokens.list per user. If
//     saas_identities is empty (e.g., directory sync has not run yet)
//     the sweep returns 0 grants without errors so the cursor still
//     surfaces a "last_synced_at" heartbeat in the connectors UI.
//   - Each unique OAuth app produces one security_assets row with
//     type=OAUTH_APP and labels=['shadow-it']; one oauth_app_grants row
//     is upserted per (app, user). The unique constraint
//     (organization_id, integration_id, external_app_id, user_email)
//     idempotently converges across retries.
//   - HTTP failures on a single user log and are surfaced on the
//     cursor's last_error; one user with a token-list permission issue
//     must not abort the whole sweep.
package googleworkspaceoauthsync

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
	"strings"
	"time"

	"github.com/writer/aperio/internal/runtimeutil"
)

const (
	defaultSyncInterval = 30 * time.Minute
	tokenURL            = "https://oauth2.googleapis.com/token"
	directoryTokensURL  = "https://admin.googleapis.com/admin/directory/v1/users/%s/tokens"
)

type OAuthConfig struct {
	ClientID     string
	ClientSecret string
}

type OAuthResolver interface {
	ResolveGoogleOAuthClient(ctx context.Context, organizationID string) (OAuthConfig, bool)
}

type Sync struct {
	db         *sql.DB
	httpClient *http.Client
	resolver   OAuthResolver
	interval   time.Duration
	nowFn      func() time.Time
}

func New(db *sql.DB, resolver OAuthResolver) *Sync {
	return &Sync{
		db:         db,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		resolver:   resolver,
		interval:   defaultSyncInterval,
		nowFn:      time.Now,
	}
}

func (s *Sync) WithInterval(d time.Duration) *Sync  { s.interval = d; return s }
func (s *Sync) WithHTTPClient(c *http.Client) *Sync { s.httpClient = c; return s }
func (s *Sync) WithNowFn(fn func() time.Time) *Sync { s.nowFn = fn; return s }

func (s *Sync) Run(ctx context.Context) error {
	if err := s.Tick(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("googleworkspaceoauthsync: first tick failed: %v", err)
	}
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := s.Tick(ctx); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("googleworkspaceoauthsync: tick failed: %v", err)
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

type identityRow struct {
	ExternalID  string
	Email       string
	DisplayName string
}

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
			log.Printf("googleworkspaceoauthsync: integ=%s sync failed: %v", integ.ID, err)
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

func (s *Sync) listIdentities(ctx context.Context, integrationID string) ([]identityRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT external_id, COALESCE(email, ''), COALESCE(display_name, '')
		FROM saas_identities
		WHERE integration_id = $1 AND status <> 'SUSPENDED'
	`, integrationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []identityRow
	for rows.Next() {
		var r identityRow
		if err := rows.Scan(&r.ExternalID, &r.Email, &r.DisplayName); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

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
	identities, err := s.listIdentities(ctx, integ.ID)
	if err != nil {
		return fmt.Errorf("list identities: %w", err)
	}
	now := s.nowFn().UTC()
	appsByClientID := map[string]parsedToken{}
	grantCount := 0
	attemptedUsers := 0
	failedUsers := 0
	var firstFailure error
	for _, identity := range identities {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		userKey := identity.ExternalID
		if userKey == "" {
			userKey = identity.Email
		}
		if userKey == "" {
			continue
		}
		attemptedUsers++
		tokens, err := s.listTokensForUser(ctx, accessToken, userKey)
		if err != nil {
			// Permission errors for one user (e.g., suspended at Google's
			// side after our row was last refreshed) must not abort the
			// sweep. Surface to the integration-level cursor and move on.
			log.Printf("googleworkspaceoauthsync: integ=%s user=%s tokens.list failed: %v", integ.ID, identity.Email, err)
			failedUsers++
			if firstFailure == nil {
				firstFailure = err
			}
			continue
		}
		for _, t := range tokens {
			parsed := parseToken(t)
			if parsed.ClientID == "" {
				continue
			}
			appRisk := parsed
			if existing, ok := appsByClientID[parsed.ClientID]; ok {
				appRisk = mergeOAuthAppToken(existing, parsed)
			}
			appsByClientID[parsed.ClientID] = appRisk
			assetID, err := s.upsertOauthAsset(ctx, integ, appRisk, now, true)
			if err != nil {
				return fmt.Errorf("upsert oauth asset %s: %w", parsed.ClientID, err)
			}
			if err := s.upsertOauthGrant(ctx, integ, assetID, parsed, identity, now); err != nil {
				return fmt.Errorf("upsert oauth grant %s/%s: %w", parsed.ClientID, identity.Email, err)
			}
			grantCount++
		}
	}
	// A sweep where every attempted user errored is almost always a
	// credential/scope misconfiguration (e.g., the exchanged access token
	// lacks the Admin Directory token-read scope -> all users return 403).
	// Without this guard the cursor would record last_error=NULL with
	// last_grant_count=0, which is indistinguishable from a tenant that
	// genuinely has zero OAuth grants — masking a total failure as a
	// clean empty sweep. Promote the all-fail case to an integration-
	// level error so the connectors UI can surface it. The partial-fail
	// case still writes a heartbeat but records the count in last_error
	// so the operator can see degradation without losing the successful
	// rows.
	if attemptedUsers > 0 && failedUsers == attemptedUsers && firstFailure != nil {
		return fmt.Errorf("tokens.list failed for all %d directory users: %w", attemptedUsers, firstFailure)
	}
	if attemptedUsers > 0 && failedUsers == 0 {
		if err := s.pruneStaleOauthGrants(ctx, integ, now); err != nil {
			return fmt.Errorf("prune stale oauth grants: %w", err)
		}
		for _, appRisk := range appsByClientID {
			if _, err := s.upsertOauthAsset(ctx, integ, appRisk, now, false); err != nil {
				return fmt.Errorf("refresh oauth asset risk %s: %w", appRisk.ClientID, err)
			}
		}
	}
	s.touchCursor(ctx, integ.ID, len(appsByClientID), grantCount, failedUsers, attemptedUsers)
	return nil
}

func (s *Sync) listTokensForUser(ctx context.Context, accessToken, userKey string) ([]googleToken, error) {
	endpoint := fmt.Sprintf(directoryTokensURL, url.PathEscape(userKey))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		// Google returns 404 when the user has zero authorized tokens.
		return nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := string(body)
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		return nil, fmt.Errorf("google directory tokens api %d: %s", resp.StatusCode, snippet)
	}
	var decoded googleTokensResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, fmt.Errorf("decode tokens response: %w", err)
	}
	return decoded.Items, nil
}

// upsertOauthAsset writes (or refreshes) the security_assets row that
// represents one third-party OAuth application. security_assets has no
// natural unique that lets us upsert by (org, integration, external_id),
// so we derive a deterministic id and upsert by primary key. Repeated
// sweeps converge on the same id idempotently.
func (s *Sync) upsertOauthAsset(ctx context.Context, integ integrationRow, p parsedToken, now time.Time, preserveExistingRisk bool) (string, error) {
	id := "ast_oauth_" + integ.ID + "_" + p.ClientID
	risk := googleOAuthAssetRisk(p.Scopes)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO security_assets (
			id, organization_id, integration_id, type, provider, external_id,
			name, summary, criticality, contains_sensitive_data, exposure_level,
			is_privileged, risk_score, labels, last_observed_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, 'OAUTH_APP'::"SecurityAssetType", 'GOOGLE_WORKSPACE'::"SaaSProvider", $4,
			$5, $6, $7::"AssetCriticality", $8, 'TRUSTED_EXTERNAL'::"AssetExposureLevel",
			$9, $10, ARRAY['shadow-it']::text[], $11, NOW(), NOW()
		)
		ON CONFLICT (id) DO UPDATE SET
			name                    = EXCLUDED.name,
			summary                 = EXCLUDED.summary,
			criticality             = CASE WHEN $12 AND security_assets.risk_score > EXCLUDED.risk_score THEN security_assets.criticality ELSE EXCLUDED.criticality END,
			contains_sensitive_data = CASE WHEN $12 THEN security_assets.contains_sensitive_data OR EXCLUDED.contains_sensitive_data ELSE EXCLUDED.contains_sensitive_data END,
			is_privileged           = CASE WHEN $12 THEN security_assets.is_privileged OR EXCLUDED.is_privileged ELSE EXCLUDED.is_privileged END,
			risk_score              = CASE WHEN $12 THEN GREATEST(security_assets.risk_score, EXCLUDED.risk_score) ELSE EXCLUDED.risk_score END,
			last_observed_at        = EXCLUDED.last_observed_at,
			updated_at              = NOW()
	`, id, integ.OrganizationID, integ.ID, p.ClientID, p.DisplayName(), p.Summary(), risk.criticality, risk.containsSensitiveData, risk.isPrivileged, risk.riskScore, now, preserveExistingRisk)
	if err != nil {
		return "", err
	}
	return id, nil
}

func (s *Sync) upsertOauthGrant(ctx context.Context, integ integrationRow, assetID string, p parsedToken, identity identityRow, now time.Time) error {
	// oauth_app_grants has TWO uniqueness constraints: the primary key id
	// and the natural-key unique on (organization_id, integration_id,
	// external_app_id, user_email). The upsert can only arbitrate on ONE
	// of them, and the OTHER must never collide for a given upsert call
	// or the INSERT will raise an unabsorbable violation that wedges the
	// integration sweep on every subsequent run.
	//
	// We arbitrate on the natural key (user_email) and derive the PK from
	// the SAME tuple (shortHash of email-or-external-id), so the two keys
	// move together:
	//
	//   * Recreate (email reused, new external_id):
	//     same email → same PK → same arbiter tuple → quiet UPDATE.
	//   * Rename (external_id stable, email changes):
	//     new email → new PK → arbiter miss → fresh INSERT with new id,
	//     no PK collision. The stale old-email row is left behind until
	//     successful-sweep cleanup proves it is no longer observed.
	//   * Empty external_id (already covered by sync_test):
	//     userKey falls back to email so two distinct users never share a
	//     PK suffix.
	userKey := identity.Email
	if userKey == "" {
		userKey = identity.ExternalID
	}
	id := "grant_" + integ.ID + "_" + p.ClientID + "_" + shortHash(userKey)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oauth_app_grants (
			id, organization_id, integration_id, asset_id, provider, external_app_id,
			app_display_name, user_email, user_external_id, user_display_name,
			scopes, anonymous, native_app, last_observed_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, 'GOOGLE_WORKSPACE'::"SaaSProvider", $5,
			$6, $7, $8, $9,
			$10::text[], $11, $12, $13, NOW(), NOW()
		)
		ON CONFLICT (organization_id, integration_id, external_app_id, user_email) DO UPDATE SET
			asset_id           = EXCLUDED.asset_id,
			app_display_name   = EXCLUDED.app_display_name,
			user_external_id   = EXCLUDED.user_external_id,
			user_display_name  = EXCLUDED.user_display_name,
			scopes             = EXCLUDED.scopes,
			anonymous          = EXCLUDED.anonymous,
			native_app         = EXCLUDED.native_app,
			last_observed_at   = EXCLUDED.last_observed_at,
			updated_at         = NOW()
	`,
		id, integ.OrganizationID, integ.ID, assetID, p.ClientID,
		p.DisplayName(), identity.Email, identity.ExternalID, identity.DisplayName,
		stringArrayLiteral(p.Scopes), p.Anonymous, p.NativeApp, now,
	)
	return err
}

func (s *Sync) pruneStaleOauthGrants(ctx context.Context, integ integrationRow, cutoff time.Time) error {
	if _, err := s.db.ExecContext(ctx, `
		DELETE FROM oauth_app_grants
		WHERE organization_id = $1
		  AND integration_id = $2
		  AND provider = 'GOOGLE_WORKSPACE'::"SaaSProvider"
		  AND last_observed_at < $3
	`, integ.OrganizationID, integ.ID, cutoff); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM security_assets sa
		WHERE sa.organization_id = $1
		  AND sa.integration_id = $2
		  AND sa.type = 'OAUTH_APP'::"SecurityAssetType"
		  AND sa.provider = 'GOOGLE_WORKSPACE'::"SaaSProvider"
		  AND 'shadow-it' = ANY(sa.labels)
		  AND sa.last_observed_at < $3
		  AND NOT EXISTS (
			SELECT 1 FROM oauth_app_grants g
			WHERE g.asset_id = sa.id
		  )
	`, integ.OrganizationID, integ.ID, cutoff)
	return err
}

func (s *Sync) touchCursor(ctx context.Context, integrationID string, appCount, grantCount, failedUsers, attemptedUsers int) {
	// Partial failure: keep the successfully-collected counts visible but
	// note the degradation in last_error so a connectors-page operator
	// sees the WARN-level state instead of a deceptively-clean heartbeat.
	var partialErr any
	if failedUsers > 0 && failedUsers < attemptedUsers {
		msg := fmt.Sprintf("tokens.list failed for %d of %d directory users", failedUsers, attemptedUsers)
		if len(msg) > 480 {
			msg = msg[:480]
		}
		partialErr = msg
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO google_workspace_oauth_sync_cursors
			(integration_id, last_synced_at, last_app_count, last_grant_count, last_error)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (integration_id) DO UPDATE SET
			last_synced_at   = EXCLUDED.last_synced_at,
			last_app_count   = EXCLUDED.last_app_count,
			last_grant_count = EXCLUDED.last_grant_count,
			last_error       = EXCLUDED.last_error
	`, integrationID, s.nowFn().UTC(), appCount, grantCount, partialErr)
	if err != nil {
		log.Printf("googleworkspaceoauthsync: touchCursor failed integ=%s: %v", integrationID, err)
	}
}

func (s *Sync) recordError(ctx context.Context, integrationID string, syncErr error) {
	msg := syncErr.Error()
	if len(msg) > 480 {
		msg = msg[:480]
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO google_workspace_oauth_sync_cursors
			(integration_id, last_synced_at, last_app_count, last_grant_count, last_error)
		VALUES ($1, $2, 0, 0, $3)
		ON CONFLICT (integration_id) DO UPDATE SET
			last_error = EXCLUDED.last_error
	`, integrationID, s.nowFn().UTC(), msg)
	if err != nil {
		log.Printf("googleworkspaceoauthsync: recordError failed integ=%s: %v", integrationID, err)
	}
}

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
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", err
	}
	if decoded.AccessToken == "" {
		return "", errors.New("token exchange response missing access_token")
	}
	return decoded.AccessToken, nil
}

// shortHash returns the first 12 hex chars of sha256(value). Used to
// derive a collision-resistant PK fragment from a userKey that may be a
// raw email or an external_id, both of which can contain characters
// (like `@` or `.`) that are inconvenient in an opaque id.
func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:6])
}

// stringArrayLiteral renders a Go []string as a Postgres array literal
// string that pgx will bind safely to a text[] column. Avoids the
// pgtype.Array dependency for this single insert path.
func stringArrayLiteral(values []string) string {
	if len(values) == 0 {
		return "{}"
	}
	escaped := make([]string, len(values))
	for i, v := range values {
		v = strings.ReplaceAll(v, `\`, `\\`)
		v = strings.ReplaceAll(v, `"`, `\"`)
		escaped[i] = `"` + v + `"`
	}
	return "{" + strings.Join(escaped, ",") + "}"
}
