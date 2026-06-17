package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"
	"sort"
	"time"
)

// This file ports the security overview computation from the original
// apps/api/src/routes/security.ts getOverview handler into Go. The SQL loaders
// are deliberately kept separate from computeSecurityOverview so the scoring
// and graph logic can be unit-tested without a database.

const dormantIdentityWindow = 30 * 24 * time.Hour

var googleMailboxStateRuleIDs = map[string]struct{}{
	"google_workspace.email_forwarding_enabled":          {},
	"google_workspace.mailbox_delegation_granted":        {},
	"google_workspace.forwarding_delegate_send_as_combo": {},
}

var googleDwdScopes = []string{
	"https://www.googleapis.com/auth/gmail.settings.basic",
	"https://www.googleapis.com/auth/gmail.settings.sharing",
}

var dataAssetTypes = map[string]struct{}{
	"DATA_RESOURCE": {},
	"WORKSPACE":     {},
	"VAULT":         {},
	"REPOSITORY":    {},
}

type overviewIdentity struct {
	ID                  string
	IntegrationID       string
	Provider            string
	ExternalID          string
	Email               string
	DisplayName         string
	Kind                string
	Status              string
	Role                string
	LinkedAssetIDs      []string
	MfaEnabled          sql.NullBool
	IsPrivileged        bool
	IsExternal          bool
	LastObservedAt      sql.NullTime
	RiskScore           int
	IntegrationProvider string
	IntegrationName     string
}

type overviewFinding struct {
	ID              string
	Title           string
	RiskScore       int
	IntegrationID   string
	IntegrationName string
	AssetID         string
	RuleID          string
	SourceEventID   string
}

type overviewGoogleIntegration struct {
	ID                 string
	Provider           string
	DisplayName        string
	ExternalAccountID  string
	Status             string
	Mode               string
	LastSyncAt         sql.NullTime
	CreatedAt          time.Time
	MailboxClientEmail string
	HasMailboxKey      bool
}

type computedIdentity struct {
	json           map[string]any
	entityID       string
	nodeID         string
	integrationID  string
	kind           string
	isExternal     bool
	privileged     bool
	riskScore      int
	name           string
	linkedAssetIDs []string
}

func (a *App) loadOverviewIdentities(ctx context.Context, organizationID string) ([]overviewIdentity, error) {
	rows, err := a.db.QueryContext(ctx, `
		SELECT si.id, COALESCE(si.integration_id, ''), si.provider::text, si.external_id,
		       COALESCE(si.email, ''), COALESCE(si.display_name, ''), si.kind::text, si.status::text,
		       COALESCE(si.role, ''), array_to_json(si.linked_asset_ids)::text, si.mfa_enabled, si.is_privileged,
		       si.is_external, si.last_observed_at, si.risk_score,
		       COALESCE(ic.provider::text, ''), COALESCE(ic.display_name, '')
		FROM saas_identities si
		LEFT JOIN integration_connections ic ON ic.id = si.integration_id
		WHERE si.organization_id = $1
		ORDER BY si.risk_score DESC, si.last_observed_at DESC NULLS LAST
	`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	identities := []overviewIdentity{}
	for rows.Next() {
		var row overviewIdentity
		var linkedAssetIDsJSON string
		if err := rows.Scan(
			&row.ID, &row.IntegrationID, &row.Provider, &row.ExternalID,
			&row.Email, &row.DisplayName, &row.Kind, &row.Status,
			&row.Role, &linkedAssetIDsJSON, &row.MfaEnabled, &row.IsPrivileged,
			&row.IsExternal, &row.LastObservedAt, &row.RiskScore,
			&row.IntegrationProvider, &row.IntegrationName,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(linkedAssetIDsJSON), &row.LinkedAssetIDs)
		identities = append(identities, row)
	}
	return identities, rows.Err()
}

func (a *App) loadOverviewOpenFindings(ctx context.Context, organizationID string) ([]overviewFinding, error) {
	rows, err := a.db.QueryContext(ctx, `
		SELECT sf.id, sf.title, sf.risk_score, COALESCE(sf.integration_id, ''),
		       COALESCE(ic.display_name, ''), COALESCE(sf.asset_id, ''),
		       COALESCE(sf.evidence->>'ruleId', ''),
		       COALESCE(sf.evidence->>'sourceEventId', '')
		FROM security_findings sf
		LEFT JOIN integration_connections ic ON ic.id = sf.integration_id
		WHERE sf.organization_id = $1 AND sf.status = 'OPEN'
		ORDER BY sf.risk_score DESC, sf.detected_at DESC
	`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	findings := []overviewFinding{}
	for rows.Next() {
		var row overviewFinding
		if err := rows.Scan(&row.ID, &row.Title, &row.RiskScore, &row.IntegrationID, &row.IntegrationName, &row.AssetID, &row.RuleID, &row.SourceEventID); err != nil {
			return nil, err
		}
		findings = append(findings, row)
	}
	return findings, rows.Err()
}

func (a *App) loadOverviewGoogleIntegrations(ctx context.Context, organizationID string) ([]overviewGoogleIntegration, error) {
	rows, err := a.db.QueryContext(ctx, `
		SELECT id, provider::text, display_name, external_account_id, status::text, mode::text,
		       last_sync_at, created_at, COALESCE(google_mailbox_scan_client_email, ''),
		       (encrypted_google_mailbox_scan_private_key IS NOT NULL)
		FROM integration_connections
		WHERE organization_id = $1 AND provider = 'GOOGLE_WORKSPACE'
	`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	integrations := []overviewGoogleIntegration{}
	for rows.Next() {
		var row overviewGoogleIntegration
		if err := rows.Scan(&row.ID, &row.Provider, &row.DisplayName, &row.ExternalAccountID, &row.Status, &row.Mode, &row.LastSyncAt, &row.CreatedAt, &row.MailboxClientEmail, &row.HasMailboxKey); err != nil {
			return nil, err
		}
		integrations = append(integrations, row)
	}
	return integrations, rows.Err()
}

func computeSecurityOverview(
	identityRows []overviewIdentity,
	assets []securityAssetRow,
	exceptions []riskExceptionRow,
	findings []overviewFinding,
	googleIntegrations []overviewGoogleIntegration,
) map[string]any {
	now := time.Now()

	sortedAssets := append([]securityAssetRow{}, assets...)
	// Sort once by risk so all downstream sections use the same deterministic
	// ordering for top assets, graph traversal, and attack-path entry selection.
	sort.SliceStable(sortedAssets, func(i, j int) bool {
		if sortedAssets[i].RiskScore != sortedAssets[j].RiskScore {
			return sortedAssets[i].RiskScore > sortedAssets[j].RiskScore
		}
		return sortedAssets[i].Name < sortedAssets[j].Name
	})

	assetMap := make(map[string]securityAssetRow, len(sortedAssets))
	applicationByIntegration := map[string]securityAssetRow{}
	for _, asset := range sortedAssets {
		assetMap[asset.ID] = asset
		if asset.Type == "APPLICATION" && asset.IntegrationID != "" {
			// The application asset represents the SaaS control plane for a
			// provider connection; child assets and identities route through it.
			applicationByIntegration[asset.IntegrationID] = asset
		}
	}

	identities := make([]computedIdentity, 0, len(identityRows))
	for _, row := range identityRows {
		identities = append(identities, computeIdentity(row, assetMap, applicationByIntegration, now))
	}
	sort.SliceStable(identities, func(i, j int) bool {
		return identities[i].riskScore > identities[j].riskScore
	})

	graphNodes := []any{}
	for _, identity := range identities {
		exposure := "INTERNAL"
		if identity.isExternal {
			exposure = "TRUSTED_EXTERNAL"
		}
		criticality := "MEDIUM"
		if identity.privileged {
			criticality = "HIGH"
		}
		graphNodes = append(graphNodes, map[string]any{
			"id": identity.nodeID, "label": identity.name, "kind": identity.kind,
			"riskScore": identity.riskScore, "privileged": identity.privileged,
			"exposureLevel": exposure, "criticality": criticality,
		})
	}
	for _, asset := range sortedAssets {
		graphNodes = append(graphNodes, map[string]any{
			"id": "asset:" + asset.ID, "label": asset.Name, "kind": asset.Type,
			"riskScore": asset.RiskScore, "privileged": asset.IsPrivileged,
			"exposureLevel": asset.ExposureLevel, "criticality": asset.Criticality,
		})
	}

	graphEdges := []any{}
	for _, identity := range identities {
		// Preserve linked asset order while removing duplicates so the graph does
		// not render parallel edges for identities connected by multiple sources.
		ordered := []string{}
		seen := map[string]struct{}{}
		add := func(id string) {
			if id == "" {
				return
			}
			if _, ok := seen[id]; ok {
				return
			}
			seen[id] = struct{}{}
			ordered = append(ordered, id)
		}
		for _, assetID := range identity.linkedAssetIDs {
			add(assetID)
		}
		if identity.integrationID != "" {
			// Identities discovered from an integration are also connected to the
			// integration's application asset, even when no explicit asset link row
			// exists yet.
			if app, ok := applicationByIntegration[identity.integrationID]; ok {
				add(app.ID)
			}
		}
		relationship := "access"
		if identity.privileged {
			relationship = "privileged_access"
		}
		for _, assetID := range ordered {
			if _, ok := assetMap[assetID]; !ok {
				continue
			}
			graphEdges = append(graphEdges, map[string]any{
				"id":               "identity-access:" + identity.entityID + ":" + assetID,
				"sourceId":         identity.nodeID,
				"targetId":         "asset:" + assetID,
				"relationshipType": relationship,
			})
		}
	}
	for _, asset := range sortedAssets {
		application, ok := lookupApplicationAsset(asset, applicationByIntegration)
		if !ok || application.ID == asset.ID {
			continue
		}
		if asset.Type == "OAUTH_APP" || asset.Type == "SERVICE_ACCOUNT" {
			// OAuth apps and service accounts are modeled as automation entry
			// points into the owning application.
			relationship := "automation_access"
			if asset.Type == "OAUTH_APP" {
				relationship = "admin_scopes"
			}
			graphEdges = append(graphEdges, map[string]any{
				"id":               "entry:" + asset.ID + ":" + application.ID,
				"sourceId":         "asset:" + asset.ID,
				"targetId":         "asset:" + application.ID,
				"relationshipType": relationship,
			})
		}
		if _, isData := dataAssetTypes[asset.Type]; isData {
			// Data assets hang under the application control plane to make blast
			// radius paths readable in the UI graph.
			graphEdges = append(graphEdges, map[string]any{
				"id":               "contains:" + application.ID + ":" + asset.ID,
				"sourceId":         "asset:" + application.ID,
				"targetId":         "asset:" + asset.ID,
				"relationshipType": "contains_data",
			})
		}
	}

	oauthAppRows := []securityAssetRow{}
	dataAssetRows := []securityAssetRow{}
	ownershipGapRows := []securityAssetRow{}
	for _, asset := range sortedAssets {
		if asset.Type == "OAUTH_APP" {
			oauthAppRows = append(oauthAppRows, asset)
		}
		_, isData := dataAssetTypes[asset.Type]
		if asset.ContainsSensitiveData || isData || asset.ExposureLevel != "INTERNAL" {
			dataAssetRows = append(dataAssetRows, asset)
		}
		if asset.OwnershipStatus != "ASSIGNED" || (asset.OwnerID == "" && asset.BusinessOwnerID == "") {
			ownershipGapRows = append(ownershipGapRows, asset)
		}
	}

	oauthApps := serializeAssetRows(oauthAppRows)
	dataAssets := serializeAssetRows(dataAssetRows)
	ownershipGaps := serializeAssetRows(ownershipGapRows)

	activeExceptions := []any{}
	for _, exception := range exceptions {
		if effectiveExceptionActive(exception, now) {
			// Only active, unexpired exceptions should influence the current
			// security overview; historical exceptions stay in audit/log views.
			activeExceptions = append(activeExceptions, protoJSON(exception.toProto()))
		}
	}

	attackPaths := computeAttackPaths(findings, identities, sortedAssets, assetMap, applicationByIntegration, exceptions, now)
	domainWideDelegations := computeDomainWideDelegations(googleIntegrations, findings)

	topBlastRadiusScore := 0
	if len(attackPaths) > 0 {
		if score, ok := attackPaths[0]["score"].(int); ok {
			topBlastRadiusScore = score
		}
	}

	privilegedIdentities := 0
	adminWithoutMfa := 0
	for _, row := range identityRows {
		if row.IsPrivileged {
			privilegedIdentities++
			if row.MfaEnabled.Valid && !row.MfaEnabled.Bool {
				adminWithoutMfa++
			}
		}
	}
	riskyOauthApps := 0
	for _, asset := range oauthAppRows {
		if asset.RiskScore >= 70 {
			riskyOauthApps++
		}
	}
	exposedDataAssets := 0
	for _, asset := range dataAssetRows {
		if asset.ExposureLevel != "INTERNAL" {
			exposedDataAssets++
		}
	}

	identitiesJSON := make([]any, 0, len(identities))
	for _, identity := range identities {
		identitiesJSON = append(identitiesJSON, identity.json)
	}

	return map[string]any{
		"summary": map[string]any{
			"privilegedIdentities":      privilegedIdentities,
			"adminIdentitiesWithoutMfa": adminWithoutMfa,
			"riskyOauthApps":            riskyOauthApps,
			"exposedDataAssets":         exposedDataAssets,
			"unownedAssets":             len(ownershipGapRows),
			"activeExceptions":          len(activeExceptions),
			"topBlastRadiusScore":       topBlastRadiusScore,
		},
		"identities":            identitiesJSON,
		"graph":                 map[string]any{"nodes": graphNodes, "edges": graphEdges},
		"oauthApps":             oauthApps,
		"dataAssets":            dataAssets,
		"attackPaths":           attackPaths,
		"ownershipGaps":         ownershipGaps,
		"exceptions":            activeExceptions,
		"domainWideDelegations": domainWideDelegations,
	}
}

func computeIdentity(row overviewIdentity, assetMap map[string]securityAssetRow, applicationByIntegration map[string]securityAssetRow, now time.Time) computedIdentity {
	var application *securityAssetRow
	if row.IntegrationID != "" {
		if app, ok := applicationByIntegration[row.IntegrationID]; ok {
			application = &app
		}
	}
	linkedSet := map[string]struct{}{}
	if application != nil {
		// Count the provider application as a linked asset for identities observed
		// through an integration, even if discovery has not attached explicit rows.
		linkedSet[application.ID] = struct{}{}
	}
	for _, assetID := range row.LinkedAssetIDs {
		if _, ok := assetMap[assetID]; !ok {
			continue
		}
		if application != nil && assetID == application.ID {
			continue
		}
		linkedSet[assetID] = struct{}{}
	}
	linkedCount := len(linkedSet)

	dormant := row.Status == "DORMANT" || (row.LastObservedAt.Valid && now.Sub(row.LastObservedAt.Time) > dormantIdentityWindow)

	baseRisk := row.RiskScore
	// Identity risk blends privilege, exposure, MFA state, dormant access, and
	// fanout breadth. The score is intentionally explainable to support UI labels.
	if baseRisk <= 0 {
		score := 20
		if row.IsPrivileged {
			score = 55
		}
		if row.MfaEnabled.Valid && !row.MfaEnabled.Bool {
			score += 20
		}
		if row.IsExternal {
			score += 10
		}
		if dormant {
			score += 10
		}
		linkBonus := linkedCount * 3
		if linkBonus > 10 {
			linkBonus = 10
		}
		score += linkBonus
		if score > 100 {
			score = 100
		}
		baseRisk = score
	}

	name := row.DisplayName
	if name == "" {
		name = row.Email
	}
	if name == "" {
		name = row.ExternalID
	}
	status := row.Status
	if dormant {
		status = "DORMANT"
	}

	var mfa any
	if row.MfaEnabled.Valid {
		mfa = row.MfaEnabled.Bool
	}
	var provider any
	if row.Provider != "" {
		provider = row.Provider
	}
	var integration any
	if row.IntegrationID != "" {
		integration = map[string]any{"id": row.IntegrationID, "provider": row.IntegrationProvider, "displayName": row.IntegrationName}
	}
	var email any
	if row.Email != "" {
		email = row.Email
	}
	role := row.Role
	if role == "" {
		role = "Unknown"
	}

	jsonObj := map[string]any{
		"id":               "identity:" + row.ID,
		"entityId":         row.ID,
		"kind":             row.Kind,
		"name":             name,
		"email":            email,
		"provider":         provider,
		"integration":      integration,
		"role":             role,
		"privileged":       row.IsPrivileged,
		"mfaEnabled":       mfa,
		"status":           status,
		"isExternal":       row.IsExternal,
		"lastObservedAt":   nullTimeCompat(row.LastObservedAt),
		"linkedAssetCount": linkedCount,
		"riskScore":        baseRisk,
	}
	return computedIdentity{
		json: jsonObj, entityID: row.ID, nodeID: "identity:" + row.ID,
		integrationID: row.IntegrationID, kind: row.Kind, isExternal: row.IsExternal,
		privileged: row.IsPrivileged, riskScore: baseRisk, name: name, linkedAssetIDs: row.LinkedAssetIDs,
	}
}

func computeAttackPaths(
	findings []overviewFinding,
	identities []computedIdentity,
	sortedAssets []securityAssetRow,
	assetMap map[string]securityAssetRow,
	applicationByIntegration map[string]securityAssetRow,
	exceptions []riskExceptionRow,
	now time.Time,
) []map[string]any {
	paths := []map[string]any{}
	for _, finding := range findings {
		var findingAsset *securityAssetRow
		if finding.AssetID != "" {
			if asset, ok := assetMap[finding.AssetID]; ok {
				findingAsset = &asset
			}
		}
		application, hasApplication := applicationByIntegration[finding.IntegrationID]

		var targets []securityAssetRow
		if findingAsset != nil {
			targets = []securityAssetRow{*findingAsset}
		} else {
			// Findings without a direct asset are projected onto assets in the same
			// integration; this keeps provider-level signals visible in blast-radius
			// analysis instead of dropping them from the overview.
			for _, asset := range sortedAssets {
				if asset.IntegrationID == finding.IntegrationID && asset.Type != "APPLICATION" {
					targets = append(targets, asset)
				}
			}
			if len(targets) == 0 && hasApplication {
				targets = []securityAssetRow{application}
			}
		}

		for _, target := range targets {
			entryAsset := highestRiskEntryAsset(sortedAssets, target.IntegrationID)
			entryIdentity := highestRiskEntryIdentity(identities, target, entryAsset, hasApplication, application)

			ownerEmail := firstNonEmpty(target.OwnerEmail, target.BusinessOwnerEmail)
			if ownerEmail == "" && entryAsset != nil {
				ownerEmail = firstNonEmpty(entryAsset.OwnerEmail, entryAsset.BusinessOwnerEmail)
			}

			penalty := 0
			for _, exception := range exceptions {
				if !effectiveExceptionActive(exception, now) {
					continue
				}
				if exception.FindingID == finding.ID || (exception.AssetID != "" && exception.AssetID == target.ID) {
					// Exceptions reduce prioritization but do not remove the path,
					// because accepted risk can still matter to graph context.
					penalty = -5
					break
				}
			}

			score := finding.RiskScore + int(math.Round(float64(target.RiskScore)*0.5))
			// Path score composes the detector's risk with target criticality and
			// propagation hints. Caps keep the UI scale comparable to finding risk.
			if entryAsset != nil && entryAsset.IsPrivileged {
				score += 10
			}
			if entryIdentity != nil && entryIdentity.privileged {
				score += 10
			}
			if target.ContainsSensitiveData {
				score += 10
			}
			switch target.ExposureLevel {
			case "PUBLIC":
				score += 15
			case "TRUSTED_EXTERNAL":
				score += 8
			}
			if target.IsPrivileged {
				score += 10
			}
			if target.OwnerID == "" && target.BusinessOwnerID == "" {
				score += 10
			}
			score += penalty
			if score > 100 {
				score = 100
			}

			var entryIdentityName, entryAssetName, applicationName string
			if entryIdentity != nil {
				entryIdentityName = entryIdentity.name
			}
			if entryAsset != nil {
				entryAssetName = entryAsset.Name
			}
			if hasApplication {
				applicationName = application.Name
			}
			path := uniqueNonEmpty([]string{entryIdentityName, entryAssetName, applicationName, target.Name})

			entryPoint := firstNonEmpty(entryIdentityName, entryAssetName, applicationName)
			if entryPoint == "" {
				entryPoint = "Unknown entry point"
			}
			owner := ownerEmail
			if owner == "" {
				owner = "Unassigned"
			}
			propagator := entryIdentityName
			if propagator == "" {
				propagator = finding.IntegrationName
			}

			paths = append(paths, map[string]any{
				"id":            finding.ID + ":" + target.ID,
				"title":         joinArrow(path),
				"score":         score,
				"findingTitle":  finding.Title,
				"entryPoint":    entryPoint,
				"target":        target.Name,
				"owner":         owner,
				"exposureLevel": target.ExposureLevel,
				"criticality":   target.Criticality,
				"reason":        finding.Title + " can propagate through " + propagator + " into " + target.Name + ".",
				"path":          path,
			})
		}
	}
	sort.SliceStable(paths, func(i, j int) bool {
		return paths[i]["score"].(int) > paths[j]["score"].(int)
	})
	if len(paths) > 8 {
		// The overview page is a triage surface, so return the highest-signal paths
		// rather than every possible finding/asset combination.
		paths = paths[:8]
	}
	return paths
}

func computeDomainWideDelegations(googleIntegrations []overviewGoogleIntegration, findings []overviewFinding) []map[string]any {
	openMailboxByIntegration := map[string]int{}
	for _, finding := range findings {
		if _, ok := googleMailboxStateRuleIDs[finding.RuleID]; ok && finding.IntegrationID != "" {
			openMailboxByIntegration[finding.IntegrationID]++
		}
	}

	delegations := []map[string]any{}
	for _, integration := range googleIntegrations {
		// Show configured DWD integrations and integrations with mailbox-state
		// findings; omit quiet unconfigured integrations to reduce dashboard noise.
		enabled := integration.MailboxClientEmail != "" && integration.HasMailboxKey
		openMailboxFindings := openMailboxByIntegration[integration.ID]
		if !enabled && openMailboxFindings == 0 {
			continue
		}
		scopes := []string{}
		status := "NOT_CONFIGURED"
		if enabled {
			scopes = googleDwdScopes
			status = "ENABLED"
		}
		var clientEmail any
		if integration.MailboxClientEmail != "" {
			clientEmail = integration.MailboxClientEmail
		}
		delegations = append(delegations, map[string]any{
			"integrationId":             integration.ID,
			"provider":                  integration.Provider,
			"displayName":               integration.DisplayName,
			"workspaceDomain":           integration.ExternalAccountID,
			"serviceAccountClientEmail": clientEmail,
			"scopes":                    scopes,
			"status":                    status,
			"integrationStatus":         integration.Status,
			"mode":                      integration.Mode,
			"openMailboxFindings":       openMailboxFindings,
			"lastSyncAt":                nullTimeCompat(integration.LastSyncAt),
			"configuredAt":              integration.CreatedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	sort.SliceStable(delegations, func(i, j int) bool {
		leftFindings := delegations[i]["openMailboxFindings"].(int)
		rightFindings := delegations[j]["openMailboxFindings"].(int)
		if leftFindings != rightFindings {
			return leftFindings > rightFindings
		}
		return delegations[i]["workspaceDomain"].(string) < delegations[j]["workspaceDomain"].(string)
	})
	return delegations
}

func lookupApplicationAsset(asset securityAssetRow, applicationByIntegration map[string]securityAssetRow) (securityAssetRow, bool) {
	if asset.IntegrationID == "" {
		return securityAssetRow{}, false
	}
	application, ok := applicationByIntegration[asset.IntegrationID]
	return application, ok
}

func highestRiskEntryAsset(sortedAssets []securityAssetRow, integrationID string) *securityAssetRow {
	if integrationID == "" {
		return nil
	}
	var best *securityAssetRow
	for index := range sortedAssets {
		asset := sortedAssets[index]
		if asset.IntegrationID != integrationID {
			continue
		}
		if asset.Type != "OAUTH_APP" && asset.Type != "SERVICE_ACCOUNT" {
			continue
		}
		if best == nil || asset.RiskScore > best.RiskScore {
			candidate := asset
			best = &candidate
		}
	}
	return best
}

func highestRiskEntryIdentity(identities []computedIdentity, target securityAssetRow, entryAsset *securityAssetRow, hasApplication bool, application securityAssetRow) *computedIdentity {
	var best *computedIdentity
	for index := range identities {
		identity := identities[index]
		if identity.integrationID == "" || identity.integrationID != target.IntegrationID {
			continue
		}
		qualifies := identity.privileged
		if !qualifies {
			for _, assetID := range identity.linkedAssetIDs {
				if assetID == target.ID || (entryAsset != nil && assetID == entryAsset.ID) || (hasApplication && assetID == application.ID) {
					qualifies = true
					break
				}
			}
		}
		if !qualifies {
			continue
		}
		if best == nil || identity.riskScore > best.riskScore {
			candidate := identity
			best = &candidate
		}
	}
	return best
}

func serializeAssetRows(rows []securityAssetRow) []any {
	out := []any{}
	for _, row := range rows {
		out = append(out, protoJSON(row.toProto()))
	}
	return out
}

func effectiveExceptionActive(exception riskExceptionRow, now time.Time) bool {
	if exception.Status != "ACTIVE" {
		return false
	}
	if exception.ExpiresAt.Valid && !exception.ExpiresAt.Time.After(now) {
		return false
	}
	return true
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func uniqueNonEmpty(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func joinArrow(values []string) string {
	result := ""
	for index, value := range values {
		if index > 0 {
			result += " → "
		}
		result += value
	}
	return result
}
