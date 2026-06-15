package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	aperiov1 "github.com/writer/aperio/gen/aperio/v1"
)

const (
	emailDomainHealthStaleWindow      = 12 * time.Hour
	emailDomainHealthBulkRefreshLimit = 10
	emailDomainHealthRefreshRatePath  = "/api/v1/security/email-domain-health/refresh"
)

var emailDomainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

var defaultDKIMSelectors = []string{
	"default",
	"google",
	"selector1",
	"selector2",
	"s1",
	"s2",
	"k1",
	"k2",
	"mail",
	"mx",
}

type emailDomainHealthRow struct {
	ID                string
	Domain            string
	ProviderSources   []string
	Status            string
	Score             int
	SPFStatus         string
	DKIMStatus        string
	DMARCStatus       string
	IssueCount        int
	FailingIssueCount int
	LastCheckedAt     time.Time
	Payload           emailDomainHealthPayload
}

type emailDomainHealthPayload struct {
	SPFRecords    []string                 `json:"spfRecords"`
	SPFPolicy     string                   `json:"spfPolicy"`
	SPFLookups    int                      `json:"spfLookups"`
	DMARCRecords  []string                 `json:"dmarcRecords"`
	DMARCPolicy   string                   `json:"dmarcPolicy"`
	DMARCPct      int                      `json:"dmarcPct"`
	DMARCRua      []string                 `json:"dmarcRua"`
	MXRecords     []string                 `json:"mxRecords"`
	DKIMSelectors []emailDomainDKIMPayload `json:"dkimSelectors"`
	Related       []string                 `json:"related"`
	Issues        []emailDomainIssue       `json:"issues"`
}

type emailDomainIssue struct {
	ID             string `json:"id"`
	Protocol       string `json:"protocol"`
	Severity       string `json:"severity"`
	Code           string `json:"code"`
	Title          string `json:"title"`
	Detail         string `json:"detail"`
	Recommendation string `json:"recommendation"`
}

type emailDomainDKIMPayload struct {
	Selector string `json:"selector"`
	Status   string `json:"status"`
	KeyBits  int    `json:"keyBits"`
	Record   string `json:"record"`
}

type emailDomainHistoryRow struct {
	CheckedAt  time.Time
	Status     string
	Score      int
	IssueCount int
}

type domainSource struct {
	Domain    string
	Providers []string
}

type emailDNSResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

type netEmailDNSResolver struct{}

func (netEmailDNSResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, name)
}

func (netEmailDNSResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return net.DefaultResolver.LookupMX(ctx, name)
}

func (a *App) listEmailDomainHealth(
	ctx context.Context,
	req *connect.Request[aperiov1.ListEmailDomainHealthRequest],
) (*connect.Response[aperiov1.ListEmailDomainHealthResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	sources, err := a.discoverEmailDomainSources(ctx, auth.OrganizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("email domain discovery unavailable"))
	}
	if len(sources) == 0 {
		return connect.NewResponse(&aperiov1.ListEmailDomainHealthResponse{Data: []*aperiov1.EmailDomainHealth{}}), nil
	}
	toRefresh, err := a.emailDomainSourcesNeedingRefresh(ctx, auth.OrganizationID, sources, req.Msg.RefreshIfStale, emailDomainHealthBulkRefreshLimit)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("email domain checks unavailable"))
	}
	if len(toRefresh) > 0 {
		if err := a.compatRateLimit(ctx, req.Header(), req.Peer().Addr, http.MethodPost, emailDomainHealthRefreshRatePath, typedRateLimitSubjectBody(auth)); err != nil {
			return nil, err
		}
		if _, err := a.refreshEmailDomainHealthChecks(ctx, auth.OrganizationID, toRefresh); err != nil {
			return nil, err
		}
	}
	rows, err := a.listEmailDomainHealthRows(ctx, auth.OrganizationID, sourceDomainSet(sources))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("email domain health unavailable"))
	}
	response := &aperiov1.ListEmailDomainHealthResponse{Data: make([]*aperiov1.EmailDomainHealth, 0, len(rows))}
	for _, row := range rows {
		response.Data = append(response.Data, emailDomainHealthProto(row))
	}
	return connect.NewResponse(response), nil
}

func (a *App) getEmailDomainHealth(
	ctx context.Context,
	req *connect.Request[aperiov1.GetEmailDomainHealthRequest],
) (*connect.Response[aperiov1.GetEmailDomainHealthResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	domain := normalizeDomainCandidate(req.Msg.Domain)
	if domain == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("domain is required"))
	}
	sources, err := a.discoverEmailDomainSources(ctx, auth.OrganizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("email domain discovery unavailable"))
	}
	sourceByDomain := make(map[string]domainSource, len(sources))
	for _, source := range sources {
		sourceByDomain[source.Domain] = source
	}
	if source, ok := sourceByDomain[domain]; ok {
		if err := a.ensureEmailDomainHealthChecks(ctx, auth, []domainSource{source}, true); err != nil {
			return nil, err
		}
	}
	row, err := a.getEmailDomainHealthRow(ctx, auth.OrganizationID, domain)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("email domain not found"))
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("email domain health unavailable"))
	}
	history, err := a.listEmailDomainHistory(ctx, auth.OrganizationID, domain, 20)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("email domain history unavailable"))
	}
	return connect.NewResponse(&aperiov1.GetEmailDomainHealthResponse{
		Data: emailDomainHealthDetailProto(row, history),
	}), nil
}

func (a *App) refreshEmailDomainHealth(
	ctx context.Context,
	req *connect.Request[aperiov1.RefreshEmailDomainHealthRequest],
) (*connect.Response[aperiov1.RefreshEmailDomainHealthResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	if err := a.compatRateLimit(ctx, req.Header(), req.Peer().Addr, http.MethodPost, emailDomainHealthRefreshRatePath, typedRateLimitSubjectBody(auth)); err != nil {
		return nil, err
	}
	sources, err := a.discoverEmailDomainSources(ctx, auth.OrganizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("email domain discovery unavailable"))
	}
	if len(sources) == 0 {
		return connect.NewResponse(&aperiov1.RefreshEmailDomainHealthResponse{Data: []*aperiov1.EmailDomainHealth{}}), nil
	}
	discoveredSources := append([]domainSource(nil), sources...)
	requested := strings.TrimSpace(req.Msg.Domain)
	if requested != "" {
		domain := normalizeDomainCandidate(requested)
		if domain == "" {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid domain"))
		}
		sourceByDomain := sourceDomainSet(sources)
		source, ok := sourceByDomain[domain]
		if !ok {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("domain not discovered from integrations"))
		}
		sources = []domainSource{source}
	} else {
		sources, err = a.emailDomainSourcesNeedingRefresh(ctx, auth.OrganizationID, sources, true, emailDomainHealthBulkRefreshLimit)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("email domain checks unavailable"))
		}
		if len(sources) == 0 {
			rows, err := a.listEmailDomainHealthRows(ctx, auth.OrganizationID, sourceDomainSet(discoveredSources))
			if err != nil {
				return nil, connect.NewError(connect.CodeInternal, errors.New("email domain health unavailable"))
			}
			response := &aperiov1.RefreshEmailDomainHealthResponse{Data: make([]*aperiov1.EmailDomainHealth, 0, len(rows))}
			for _, row := range rows {
				response.Data = append(response.Data, emailDomainHealthProto(row))
			}
			return connect.NewResponse(response), nil
		}
	}
	refreshSources := append([]domainSource(nil), sources...)
	updated, err := a.refreshEmailDomainHealthChecks(ctx, auth.OrganizationID, sources)
	if err != nil {
		return nil, err
	}
	a.writeCompatAudit(ctx, auth, "security.email_domain_health.refresh", "organization", auth.OrganizationID, map[string]any{
		"domains":         sourceDomainNames(refreshSources),
		"domainCount":     len(refreshSources),
		"requestedDomain": requested,
	})
	if requested == "" {
		rows, err := a.listEmailDomainHealthRows(ctx, auth.OrganizationID, sourceDomainSet(discoveredSources))
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("email domain health unavailable"))
		}
		updated = rows
	}
	response := &aperiov1.RefreshEmailDomainHealthResponse{Data: make([]*aperiov1.EmailDomainHealth, 0, len(updated))}
	for _, row := range updated {
		response.Data = append(response.Data, emailDomainHealthProto(row))
	}
	return connect.NewResponse(response), nil
}

func (a *App) ensureEmailDomainHealthChecks(ctx context.Context, auth compatAuth, sources []domainSource, refreshStale bool) error {
	toRefresh, err := a.emailDomainSourcesNeedingRefresh(ctx, auth.OrganizationID, sources, refreshStale, 0)
	if err != nil {
		return connect.NewError(connect.CodeInternal, errors.New("email domain checks unavailable"))
	}
	if len(toRefresh) == 0 {
		return nil
	}
	_, refreshErr := a.refreshEmailDomainHealthChecks(ctx, auth.OrganizationID, toRefresh)
	return refreshErr
}

func (a *App) emailDomainSourcesNeedingRefresh(ctx context.Context, organizationID string, sources []domainSource, refreshStale bool, limit int) ([]domainSource, error) {
	existing, err := a.loadEmailDomainCheckTimes(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	return emailDomainSourcesNeedingRefresh(sources, existing, time.Now().UTC(), refreshStale, limit), nil
}

func (a *App) refreshEmailDomainHealthChecks(ctx context.Context, organizationID string, sources []domainSource) ([]emailDomainHealthRow, error) {
	resolver := netEmailDNSResolver{}
	rows := make([]emailDomainHealthRow, 0, len(sources))
	for _, source := range sources {
		domainCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
		evaluated := evaluateEmailDomainHealth(domainCtx, resolver, source.Domain, source.Providers)
		cancel()
		checkedAt := time.Now().UTC()
		evaluated.Domain = source.Domain
		evaluated.ProviderSources = append([]string(nil), source.Providers...)
		evaluated.LastCheckedAt = checkedAt
		checkID, err := a.upsertEmailDomainHealthCheck(ctx, organizationID, evaluated)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("email domain health persistence failed"))
		}
		if err := a.insertEmailDomainHealthRun(ctx, organizationID, checkID, evaluated); err != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("email domain health history failed"))
		}
		rows = append(rows, evaluated)
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Domain < rows[j].Domain
	})
	return rows, nil
}

func (a *App) discoverEmailDomainSources(ctx context.Context, organizationID string) ([]domainSource, error) {
	rows, err := a.db.QueryContext(ctx, `
		SELECT provider::text, COALESCE(display_name, ''), COALESCE(external_account_id, '')
		FROM integration_connections
		WHERE organization_id = $1 AND status = 'CONNECTED'
	`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	providersByDomain := map[string]map[string]struct{}{}
	addDomain := func(provider string, candidate string) {
		domain := normalizeDomainCandidate(candidate)
		if domain == "" {
			return
		}
		seenProviders, ok := providersByDomain[domain]
		if !ok {
			seenProviders = map[string]struct{}{}
			providersByDomain[domain] = seenProviders
		}
		seenProviders[provider] = struct{}{}
	}
	for rows.Next() {
		var provider, displayName, externalAccountID string
		if err := rows.Scan(&provider, &displayName, &externalAccountID); err != nil {
			return nil, err
		}
		addDomain(provider, externalAccountID)
		addDomain(provider, displayName)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	identityRows, err := a.db.QueryContext(ctx, `
		SELECT ic.provider::text, COALESCE(si.email, ''), COALESCE(si.external_id, '')
		FROM integration_connections ic
		JOIN saas_identities si
			ON si.organization_id = ic.organization_id
			AND si.integration_id = ic.id
		WHERE ic.organization_id = $1 AND ic.status = 'CONNECTED'
	`, organizationID)
	if err != nil {
		return nil, err
	}
	defer identityRows.Close()
	for identityRows.Next() {
		var provider, email, externalID string
		if err := identityRows.Scan(&provider, &email, &externalID); err != nil {
			return nil, err
		}
		addDomain(provider, email)
		addDomain(provider, externalID)
	}
	if err := identityRows.Err(); err != nil {
		return nil, err
	}
	out := make([]domainSource, 0, len(providersByDomain))
	for domain, providers := range providersByDomain {
		list := make([]string, 0, len(providers))
		for provider := range providers {
			list = append(list, provider)
		}
		sort.Strings(list)
		out = append(out, domainSource{
			Domain:    domain,
			Providers: list,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Domain < out[j].Domain
	})
	return out, nil
}

func emailDomainSourcesNeedingRefresh(sources []domainSource, existing map[string]time.Time, now time.Time, refreshStale bool, limit int) []domainSource {
	out := make([]domainSource, 0, len(sources))
	for _, source := range sources {
		lastCheckedAt, ok := existing[source.Domain]
		if ok {
			if !refreshStale || now.Sub(lastCheckedAt.UTC()) < emailDomainHealthStaleWindow {
				continue
			}
		}
		out = append(out, source)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func normalizeDomainCandidate(raw string) string {
	candidate := strings.TrimSpace(strings.ToLower(raw))
	if candidate == "" {
		return ""
	}
	if strings.Contains(candidate, "@") {
		parts := strings.Split(candidate, "@")
		candidate = parts[len(parts)-1]
	}
	if strings.Contains(candidate, "://") {
		if parsed, err := url.Parse(candidate); err == nil && parsed.Host != "" {
			candidate = parsed.Host
		}
	}
	if strings.Contains(candidate, "/") {
		if parsed, err := url.Parse("https://" + candidate); err == nil && parsed.Host != "" {
			candidate = parsed.Host
		}
	}
	candidate = strings.Trim(candidate, "[]")
	candidate = strings.TrimSuffix(candidate, ".")
	if host, _, err := net.SplitHostPort(candidate); err == nil && host != "" {
		candidate = host
	} else if index := strings.LastIndex(candidate, ":"); index > 0 {
		candidate = candidate[:index]
	}
	if strings.HasPrefix(candidate, "www.") {
		candidate = strings.TrimPrefix(candidate, "www.")
	}
	if ip := net.ParseIP(candidate); ip != nil {
		return ""
	}
	if !emailDomainPattern.MatchString(candidate) {
		return ""
	}
	if strings.HasSuffix(candidate, ".local") || strings.HasSuffix(candidate, ".internal") {
		return ""
	}
	return candidate
}

func sourceDomainSet(sources []domainSource) map[string]domainSource {
	out := make(map[string]domainSource, len(sources))
	for _, source := range sources {
		out[source.Domain] = source
	}
	return out
}

func sourceDomainNames(sources []domainSource) []string {
	out := make([]string, 0, len(sources))
	for _, source := range sources {
		out = append(out, source.Domain)
	}
	sort.Strings(out)
	return out
}

func (a *App) loadEmailDomainCheckTimes(ctx context.Context, organizationID string) (map[string]time.Time, error) {
	rows, err := a.db.QueryContext(ctx, `
		SELECT domain, last_checked_at
		FROM email_domain_health_checks
		WHERE organization_id = $1
	`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var domain string
		var checkedAt time.Time
		if err := rows.Scan(&domain, &checkedAt); err != nil {
			return nil, err
		}
		out[domain] = checkedAt
	}
	return out, rows.Err()
}

func (a *App) upsertEmailDomainHealthCheck(ctx context.Context, organizationID string, row emailDomainHealthRow) (string, error) {
	payload, err := json.Marshal(row.Payload)
	if err != nil {
		return "", err
	}
	id := compatID("edh")
	if err := a.db.QueryRowContext(ctx, `
		INSERT INTO email_domain_health_checks (
			id,
			organization_id,
			domain,
			provider_sources,
			status,
			score,
			spf_status,
			dkim_status,
			dmarc_status,
			issue_count,
			failing_issue_count,
			payload,
			last_checked_at,
			created_at,
			updated_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,NOW(),NOW()
		)
		ON CONFLICT (organization_id, domain) DO UPDATE SET
			provider_sources = EXCLUDED.provider_sources,
			status = EXCLUDED.status,
			score = EXCLUDED.score,
			spf_status = EXCLUDED.spf_status,
			dkim_status = EXCLUDED.dkim_status,
			dmarc_status = EXCLUDED.dmarc_status,
			issue_count = EXCLUDED.issue_count,
			failing_issue_count = EXCLUDED.failing_issue_count,
			payload = EXCLUDED.payload,
			last_checked_at = EXCLUDED.last_checked_at,
			updated_at = NOW()
		RETURNING id
	`,
		id,
		organizationID,
		row.Domain,
		row.ProviderSources,
		row.Status,
		row.Score,
		row.SPFStatus,
		row.DKIMStatus,
		row.DMARCStatus,
		row.IssueCount,
		row.FailingIssueCount,
		string(payload),
		row.LastCheckedAt,
	).Scan(&id); err != nil {
		return "", err
	}
	return id, nil
}

func (a *App) insertEmailDomainHealthRun(ctx context.Context, organizationID, checkID string, row emailDomainHealthRow) error {
	payload, err := json.Marshal(row.Payload)
	if err != nil {
		return err
	}
	_, err = a.db.ExecContext(ctx, `
		INSERT INTO email_domain_health_runs (
			id,
			check_id,
			organization_id,
			domain,
			status,
			score,
			issue_count,
			payload,
			checked_at,
			created_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,NOW()
		)
	`, compatID("ehr"), checkID, organizationID, row.Domain, row.Status, row.Score, row.IssueCount, string(payload), row.LastCheckedAt)
	return err
}

func (a *App) listEmailDomainHealthRows(ctx context.Context, organizationID string, discovered map[string]domainSource) ([]emailDomainHealthRow, error) {
	rows, err := a.db.QueryContext(ctx, `
		SELECT
			id,
			domain,
			array_to_json(provider_sources)::text,
			status,
			score,
			spf_status,
			dkim_status,
			dmarc_status,
			issue_count,
			failing_issue_count,
			payload::text,
			last_checked_at
		FROM email_domain_health_checks
		WHERE organization_id = $1
		ORDER BY domain ASC
	`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]emailDomainHealthRow, 0, len(discovered))
	for rows.Next() {
		var row emailDomainHealthRow
		var providersJSON string
		var payloadJSON string
		if err := rows.Scan(
			&row.ID,
			&row.Domain,
			&providersJSON,
			&row.Status,
			&row.Score,
			&row.SPFStatus,
			&row.DKIMStatus,
			&row.DMARCStatus,
			&row.IssueCount,
			&row.FailingIssueCount,
			&payloadJSON,
			&row.LastCheckedAt,
		); err != nil {
			return nil, err
		}
		if _, ok := discovered[row.Domain]; !ok {
			continue
		}
		_ = json.Unmarshal([]byte(providersJSON), &row.ProviderSources)
		_ = json.Unmarshal([]byte(payloadJSON), &row.Payload)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (a *App) getEmailDomainHealthRow(ctx context.Context, organizationID, domain string) (emailDomainHealthRow, error) {
	var row emailDomainHealthRow
	var providersJSON string
	var payloadJSON string
	err := a.db.QueryRowContext(ctx, `
		SELECT
			id,
			domain,
			array_to_json(provider_sources)::text,
			status,
			score,
			spf_status,
			dkim_status,
			dmarc_status,
			issue_count,
			failing_issue_count,
			payload::text,
			last_checked_at
		FROM email_domain_health_checks
		WHERE organization_id = $1 AND domain = $2
	`, organizationID, domain).Scan(
		&row.ID,
		&row.Domain,
		&providersJSON,
		&row.Status,
		&row.Score,
		&row.SPFStatus,
		&row.DKIMStatus,
		&row.DMARCStatus,
		&row.IssueCount,
		&row.FailingIssueCount,
		&payloadJSON,
		&row.LastCheckedAt,
	)
	if err != nil {
		return emailDomainHealthRow{}, err
	}
	_ = json.Unmarshal([]byte(providersJSON), &row.ProviderSources)
	_ = json.Unmarshal([]byte(payloadJSON), &row.Payload)
	return row, nil
}

func (a *App) listEmailDomainHistory(ctx context.Context, organizationID, domain string, limit int) ([]emailDomainHistoryRow, error) {
	rows, err := a.db.QueryContext(ctx, `
		SELECT checked_at, status, score, issue_count
		FROM email_domain_health_runs
		WHERE organization_id = $1 AND domain = $2
		ORDER BY checked_at DESC
		LIMIT $3
	`, organizationID, domain, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]emailDomainHistoryRow, 0, limit)
	for rows.Next() {
		var row emailDomainHistoryRow
		if err := rows.Scan(&row.CheckedAt, &row.Status, &row.Score, &row.IssueCount); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func evaluateEmailDomainHealth(ctx context.Context, resolver emailDNSResolver, domain string, providers []string) emailDomainHealthRow {
	issues := make([]emailDomainIssue, 0, 8)
	payload := emailDomainHealthPayload{
		SPFRecords:    []string{},
		DMARCRecords:  []string{},
		DMARCRua:      []string{},
		MXRecords:     []string{},
		DKIMSelectors: []emailDomainDKIMPayload{},
		Related:       []string{},
		Issues:        []emailDomainIssue{},
	}

	spfTXT, spfErr := resolver.LookupTXT(ctx, domain)
	spfRecords := filterTXTPrefix(spfTXT, "v=spf1")
	payload.SPFRecords = spfRecords
	if spfErr != nil {
		issues = append(issues, issueFor("SPF", "MEDIUM", "spf_lookup_failed", "SPF lookup failed", spfErr.Error(), "Confirm authoritative DNS responds for SPF TXT records."))
	}
	if len(spfRecords) == 0 {
		issues = append(issues, issueFor("SPF", "HIGH", "spf_missing", "SPF record missing", "No SPF TXT record was found for this domain.", "Publish a single SPF TXT record that ends with '-all'."))
	}
	if len(spfRecords) > 1 {
		issues = append(issues, issueFor("SPF", "HIGH", "spf_multiple", "Multiple SPF records found", fmt.Sprintf("Detected %d SPF records.", len(spfRecords)), "Collapse to one SPF record to avoid permerror behavior."))
	}
	if len(spfRecords) > 0 {
		record := spfRecords[0]
		payload.SPFPolicy = spfTerminalPolicy(record)
		payload.SPFLookups = spfLookupCount(record)
		switch payload.SPFPolicy {
		case "+all", "all":
			issues = append(issues, issueFor("SPF", "CRITICAL", "spf_permissive_all", "SPF allows all senders", "SPF ends in '+all' which permits spoofing.", "Replace '+all' with '-all' after validating legitimate senders."))
		case "?all":
			issues = append(issues, issueFor("SPF", "HIGH", "spf_neutral_all", "SPF uses neutral policy", "SPF ends in '?all', which is not an enforcing policy.", "Replace '?all' with '-all' after validating legitimate senders."))
		case "~all":
			issues = append(issues, issueFor("SPF", "MEDIUM", "spf_softfail", "SPF uses soft-fail", "SPF ends in '~all' which is not strict enforcement.", "Move to '-all' when sender inventory is complete."))
		case "":
			issues = append(issues, issueFor("SPF", "MEDIUM", "spf_no_terminal_policy", "SPF terminal policy missing", "SPF record does not include an all-mechanism policy.", "Add a terminal '-all' policy."))
		}
		if payload.SPFLookups > 10 {
			issues = append(issues, issueFor("SPF", "HIGH", "spf_lookup_limit_exceeded", "SPF lookup count exceeds RFC limit", fmt.Sprintf("Estimated lookup count is %d.", payload.SPFLookups), "Reduce include/redirect mechanisms to 10 or fewer DNS lookups."))
		}
	}

	dmarcTXT, dmarcErr := resolver.LookupTXT(ctx, "_dmarc."+domain)
	dmarcRecords := filterTXTPrefix(dmarcTXT, "v=dmarc1")
	payload.DMARCRecords = dmarcRecords
	if dmarcErr != nil {
		issues = append(issues, issueFor("DMARC", "MEDIUM", "dmarc_lookup_failed", "DMARC lookup failed", dmarcErr.Error(), "Confirm _dmarc TXT records resolve."))
	}
	if len(dmarcRecords) == 0 {
		issues = append(issues, issueFor("DMARC", "HIGH", "dmarc_missing", "DMARC record missing", "No DMARC TXT record was found.", "Publish a DMARC record with at least p=none and reporting, then move to p=quarantine/reject."))
	} else {
		if len(dmarcRecords) > 1 {
			issues = append(issues, issueFor("DMARC", "HIGH", "dmarc_multiple", "Multiple DMARC records found", fmt.Sprintf("Detected %d DMARC records.", len(dmarcRecords)), "Keep exactly one DMARC TXT record at _dmarc.<domain>."))
		}
		tags := parseTagRecord(dmarcRecords[0])
		policy := strings.ToLower(strings.TrimSpace(tags["p"]))
		if policy == "" {
			issues = append(issues, issueFor("DMARC", "HIGH", "dmarc_policy_missing", "DMARC policy missing", "The p= tag is missing in the DMARC record.", "Add p=quarantine or p=reject after baseline monitoring."))
		} else if policy != "none" && policy != "quarantine" && policy != "reject" {
			issues = append(issues, issueFor("DMARC", "HIGH", "dmarc_policy_invalid", "DMARC policy is invalid", fmt.Sprintf("DMARC policy p=%s is not a valid value.", policy), "Set p=none, p=quarantine, or p=reject."))
		}
		payload.DMARCPolicy = strings.ToUpper(policy)
		if policy == "none" {
			issues = append(issues, issueFor("DMARC", "MEDIUM", "dmarc_policy_none", "DMARC policy is monitoring-only", "DMARC policy is set to p=none.", "Move to p=quarantine or p=reject for enforcement."))
		}
		payload.DMARCPct = 100
		if pct, err := strconv.Atoi(strings.TrimSpace(tags["pct"])); err == nil {
			payload.DMARCPct = pct
			if pct < 100 {
				issues = append(issues, issueFor("DMARC", "LOW", "dmarc_partial_pct", "DMARC enforcement is partial", fmt.Sprintf("pct=%d applies policy to only part of traffic.", pct), "Set pct=100 once confidence is high."))
			}
		}
		payload.DMARCRua = parseDMARCReportAddresses(tags["rua"])
		if len(payload.DMARCRua) == 0 {
			issues = append(issues, issueFor("DMARC", "LOW", "dmarc_rua_missing", "DMARC aggregate reporting missing", "No rua reporting address is configured.", "Configure rua=mailto:... to collect aggregate authentication reports."))
		}
	}

	foundSelectors := 0
	for _, selector := range defaultDKIMSelectors {
		recordName := selector + "._domainkey." + domain
		values, err := resolver.LookupTXT(ctx, recordName)
		if err != nil {
			continue
		}
		dkimRecords := filterTXTPrefix(values, "v=dkim1")
		if len(dkimRecords) == 0 {
			continue
		}
		foundSelectors++
		record := dkimRecords[0]
		tags := parseTagRecord(record)
		keyValue := strings.TrimSpace(tags["p"])
		keyBits, keyValid, enforceRSAThresholds := dkimKeyBits(keyValue, tags["k"])
		selectorStatus := "HEALTHY"
		if keyValue == "" {
			selectorStatus = "FAILING"
			issues = append(issues, issueFor("DKIM", "HIGH", "dkim_missing_key", "DKIM public key missing", fmt.Sprintf("Selector %s is missing p= key material.", selector), "Publish valid DKIM public key material in p=."))
		} else if !keyValid {
			selectorStatus = "FAILING"
			issues = append(issues, issueFor("DKIM", "HIGH", "dkim_invalid_key_material", "DKIM key material is malformed", fmt.Sprintf("Selector %s has invalid p= key material.", selector), "Publish valid base64-encoded DKIM public key material in p=."))
		}
		if enforceRSAThresholds && keyValid && keyBits > 0 && keyBits < 1024 {
			selectorStatus = "FAILING"
			issues = append(issues, issueFor("DKIM", "CRITICAL", "dkim_weak_key", "DKIM key is too weak", fmt.Sprintf("Selector %s key size is %d bits.", selector, keyBits), "Rotate selector to at least 2048-bit RSA key material."))
		} else if enforceRSAThresholds && keyValid && keyBits >= 1024 && keyBits < 2048 {
			if selectorStatus != "FAILING" {
				selectorStatus = "WARNING"
			}
			issues = append(issues, issueFor("DKIM", "MEDIUM", "dkim_key_short", "DKIM key length below recommended", fmt.Sprintf("Selector %s key size is %d bits.", selector, keyBits), "Rotate selector to a 2048-bit RSA key."))
		}
		payload.DKIMSelectors = append(payload.DKIMSelectors, emailDomainDKIMPayload{
			Selector: selector,
			Status:   selectorStatus,
			KeyBits:  keyBits,
			Record:   record,
		})
	}
	if foundSelectors == 0 {
		issues = append(issues, issueFor("DKIM", "HIGH", "dkim_missing", "No DKIM selectors discovered", "No known DKIM selector records were found.", "Publish DKIM selectors (for example default/selector1) with valid public keys."))
	}

	mxRecords, mxErr := resolver.LookupMX(ctx, domain)
	if mxErr != nil {
		issues = append(issues, issueFor("MX", "MEDIUM", "mx_lookup_failed", "MX lookup failed", mxErr.Error(), "Verify MX records exist and can be resolved publicly."))
	}
	if len(mxRecords) == 0 {
		issues = append(issues, issueFor("MX", "MEDIUM", "mx_missing", "MX records missing", "No MX records were found for this domain.", "Publish MX records for inbound mail delivery."))
	} else {
		sort.Slice(mxRecords, func(i, j int) bool {
			if mxRecords[i].Pref == mxRecords[j].Pref {
				return mxRecords[i].Host < mxRecords[j].Host
			}
			return mxRecords[i].Pref < mxRecords[j].Pref
		})
		for _, mx := range mxRecords {
			payload.MXRecords = append(payload.MXRecords, fmt.Sprintf("%d %s", mx.Pref, strings.TrimSuffix(mx.Host, ".")))
		}
	}

	for _, related := range []string{"_mta-sts." + domain, "_smtp._tls." + domain, "default._bimi." + domain} {
		txt, err := resolver.LookupTXT(ctx, related)
		if err != nil || len(txt) == 0 {
			continue
		}
		for _, value := range txt {
			payload.Related = append(payload.Related, fmt.Sprintf("%s TXT %s", related, strings.TrimSpace(value)))
		}
	}
	sort.Strings(payload.Related)

	sortIssues(issues)
	payload.Issues = issues
	spfStatus := protocolStatus("SPF", issues, len(payload.SPFRecords) > 0)
	dkimStatus := protocolStatus("DKIM", issues, len(payload.DKIMSelectors) > 0)
	dmarcStatus := protocolStatus("DMARC", issues, len(payload.DMARCRecords) > 0)
	score := issueScore(issues)
	status := overallStatus(spfStatus, dkimStatus, dmarcStatus, issues)
	return emailDomainHealthRow{
		Domain:            domain,
		ProviderSources:   providers,
		Status:            status,
		Score:             score,
		SPFStatus:         spfStatus,
		DKIMStatus:        dkimStatus,
		DMARCStatus:       dmarcStatus,
		IssueCount:        len(issues),
		FailingIssueCount: failingIssueCount(issues),
		Payload:           payload,
	}
}

func filterTXTPrefix(records []string, prefix string) []string {
	out := make([]string, 0, len(records))
	for _, record := range records {
		trimmed := strings.TrimSpace(record)
		if strings.HasPrefix(strings.ToLower(trimmed), strings.ToLower(prefix)) {
			out = append(out, trimmed)
		}
	}
	sort.Strings(out)
	return out
}

func issueFor(protocol, severity, code, title, detail, recommendation string) emailDomainIssue {
	return emailDomainIssue{
		ID:             protocol + ":" + code,
		Protocol:       protocol,
		Severity:       severity,
		Code:           code,
		Title:          title,
		Detail:         detail,
		Recommendation: recommendation,
	}
}

func parseTagRecord(record string) map[string]string {
	out := map[string]string{}
	for _, segment := range strings.Split(record, ";") {
		part := strings.TrimSpace(segment)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		value := strings.TrimSpace(kv[1])
		out[key] = value
	}
	return out
}

func parseDMARCReportAddresses(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return []string{}
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func spfTerminalPolicy(record string) string {
	fields := strings.Fields(strings.ToLower(record))
	for i := len(fields) - 1; i >= 0; i-- {
		field := strings.TrimSpace(fields[i])
		if strings.HasSuffix(field, "all") {
			switch {
			case strings.HasPrefix(field, "+"):
				return "+all"
			case strings.HasPrefix(field, "-"):
				return "-all"
			case strings.HasPrefix(field, "~"):
				return "~all"
			case strings.HasPrefix(field, "?"):
				return "?all"
			default:
				return "all"
			}
		}
	}
	return ""
}

func spfLookupCount(record string) int {
	fields := strings.Fields(strings.ToLower(record))
	count := 0
	for _, field := range fields {
		switch {
		case strings.HasPrefix(field, "include:"),
			strings.HasPrefix(field, "exists:"),
			strings.HasPrefix(field, "redirect="),
			field == "a",
			strings.HasPrefix(field, "a:"),
			field == "mx",
			strings.HasPrefix(field, "mx:"),
			field == "ptr",
			strings.HasPrefix(field, "ptr:"):
			count++
		}
	}
	return count
}

func dkimKeyBits(publicKey, keyType string) (int, bool, bool) {
	normalizedType := strings.ToLower(strings.TrimSpace(keyType))
	switch normalizedType {
	case "", "rsa":
		bits, ok := dkimRSAKeyBits(publicKey)
		return bits, ok, true
	case "ed25519":
		bits, ok := dkimEd25519KeyBits(publicKey)
		return bits, ok, false
	default:
		return 0, false, false
	}
}

func dkimRSAKeyBits(publicKey string) (int, bool) {
	decoded, ok := decodeDKIMPublicKey(publicKey)
	if !ok {
		return 0, false
	}
	parsed, err := x509.ParsePKIXPublicKey(decoded)
	if err == nil {
		key, ok := parsed.(*rsa.PublicKey)
		if !ok || key.N == nil || key.N.Sign() <= 0 {
			return 0, false
		}
		return key.N.BitLen(), true
	}
	key, err := x509.ParsePKCS1PublicKey(decoded)
	if err != nil || key.N == nil || key.N.Sign() <= 0 {
		return 0, false
	}
	return key.N.BitLen(), true
}

func dkimEd25519KeyBits(publicKey string) (int, bool) {
	decoded, ok := decodeDKIMPublicKey(publicKey)
	if !ok {
		return 0, false
	}
	if len(decoded) == ed25519.PublicKeySize {
		return ed25519.PublicKeySize * 8, true
	}
	parsed, err := x509.ParsePKIXPublicKey(decoded)
	if err != nil {
		return 0, false
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return 0, false
	}
	return len(key) * 8, true
}

func decodeDKIMPublicKey(publicKey string) ([]byte, bool) {
	cleaned := strings.Join(strings.Fields(publicKey), "")
	if cleaned == "" {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(cleaned)
		if err != nil {
			return nil, false
		}
	}
	if len(decoded) == 0 {
		return nil, false
	}
	return decoded, true
}

func sortIssues(issues []emailDomainIssue) {
	sort.SliceStable(issues, func(i, j int) bool {
		li := severityRank(issues[i].Severity)
		lj := severityRank(issues[j].Severity)
		if li != lj {
			return li > lj
		}
		if issues[i].Protocol != issues[j].Protocol {
			return issues[i].Protocol < issues[j].Protocol
		}
		return issues[i].Code < issues[j].Code
	})
}

func severityRank(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func issueScore(issues []emailDomainIssue) int {
	score := 100
	for _, issue := range issues {
		switch strings.ToUpper(issue.Severity) {
		case "CRITICAL":
			score -= 30
		case "HIGH":
			score -= 20
		case "MEDIUM":
			score -= 10
		case "LOW":
			score -= 5
		default:
			score -= 2
		}
	}
	if score < 0 {
		return 0
	}
	return score
}

func failingIssueCount(issues []emailDomainIssue) int {
	count := 0
	for _, issue := range issues {
		if rank := severityRank(issue.Severity); rank >= 3 {
			count++
		}
	}
	return count
}

func protocolStatus(protocol string, issues []emailDomainIssue, hasRecords bool) string {
	maxRank := -1
	for _, issue := range issues {
		if !strings.EqualFold(issue.Protocol, protocol) {
			continue
		}
		rank := severityRank(issue.Severity)
		if rank > maxRank {
			maxRank = rank
		}
	}
	switch {
	case maxRank >= 3:
		return "FAILING"
	case maxRank >= 1:
		return "WARNING"
	case hasRecords:
		return "HEALTHY"
	default:
		return "UNKNOWN"
	}
}

func overallStatus(spfStatus, dkimStatus, dmarcStatus string, issues []emailDomainIssue) string {
	for _, issue := range issues {
		if severityRank(issue.Severity) >= 3 {
			return "FAILING"
		}
	}
	for _, issue := range issues {
		if severityRank(issue.Severity) >= 1 {
			return "WARNING"
		}
	}
	if spfStatus == "UNKNOWN" && dkimStatus == "UNKNOWN" && dmarcStatus == "UNKNOWN" {
		return "UNKNOWN"
	}
	return "HEALTHY"
}

func emailDomainHealthProto(row emailDomainHealthRow) *aperiov1.EmailDomainHealth {
	return &aperiov1.EmailDomainHealth{
		Domain:            row.Domain,
		ProviderSources:   row.ProviderSources,
		Status:            row.Status,
		Score:             int32(row.Score),
		SpfStatus:         row.SPFStatus,
		DkimStatus:        row.DKIMStatus,
		DmarcStatus:       row.DMARCStatus,
		LastCheckedAt:     row.LastCheckedAt.UTC().Format(time.RFC3339Nano),
		IssueCount:        int32(row.IssueCount),
		FailingIssueCount: int32(row.FailingIssueCount),
	}
}

func emailDomainHealthDetailProto(row emailDomainHealthRow, history []emailDomainHistoryRow) *aperiov1.EmailDomainHealthDetail {
	detail := &aperiov1.EmailDomainHealthDetail{
		Domain:         emailDomainHealthProto(row),
		SpfRecords:     row.Payload.SPFRecords,
		SpfPolicy:      row.Payload.SPFPolicy,
		SpfLookupCount: int32(row.Payload.SPFLookups),
		DmarcRecords:   row.Payload.DMARCRecords,
		DmarcPolicy:    row.Payload.DMARCPolicy,
		DmarcPct:       int32(row.Payload.DMARCPct),
		DmarcRua:       row.Payload.DMARCRua,
		MxRecords:      row.Payload.MXRecords,
		DkimSelectors:  make([]*aperiov1.EmailDomainDkimSelector, 0, len(row.Payload.DKIMSelectors)),
		RelatedRecords: row.Payload.Related,
		Issues:         make([]*aperiov1.EmailDomainHealthIssue, 0, len(row.Payload.Issues)),
		History:        make([]*aperiov1.EmailDomainHealthHistoryPoint, 0, len(history)),
	}
	for _, selector := range row.Payload.DKIMSelectors {
		detail.DkimSelectors = append(detail.DkimSelectors, &aperiov1.EmailDomainDkimSelector{
			Selector: selector.Selector,
			Status:   selector.Status,
			KeyBits:  int32(selector.KeyBits),
			Record:   selector.Record,
		})
	}
	for _, issue := range row.Payload.Issues {
		detail.Issues = append(detail.Issues, &aperiov1.EmailDomainHealthIssue{
			Id:             issue.ID,
			Protocol:       issue.Protocol,
			Severity:       issue.Severity,
			Code:           issue.Code,
			Title:          issue.Title,
			Detail:         issue.Detail,
			Recommendation: issue.Recommendation,
		})
	}
	for _, point := range history {
		detail.History = append(detail.History, &aperiov1.EmailDomainHealthHistoryPoint{
			CheckedAt:  point.CheckedAt.UTC().Format(time.RFC3339Nano),
			Status:     point.Status,
			Score:      int32(point.Score),
			IssueCount: int32(point.IssueCount),
		})
	}
	return detail
}
