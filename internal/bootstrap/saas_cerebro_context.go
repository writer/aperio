package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/writer/aperio/internal/cerebroclient"
)

const (
	maxSaasCerebroClaimQueries = 8
	maxSaasCerebroClaims       = 80
	maxSaasCerebroGraphRoots   = 3
	maxSaasCerebroGraphLimit   = 12
)

type saasCerebroContextClient interface {
	ListClaims(context.Context, cerebroclient.ListClaimsRequest) (*cerebroclient.ListClaimsResponse, error)
	GetEntityNeighborhood(context.Context, string, uint32) (*cerebroclient.EntityNeighborhood, error)
}

func (a *App) WithCerebroContextClient(runtimeID string, client saasCerebroContextClient) *App {
	a.cerebroRuntimeID = strings.TrimSpace(runtimeID)
	a.cerebroContextClient = client
	return a
}

func (a *App) enrichSaasCerebroContext(ctx context.Context, organizationID string, incidentID string, raw string, findings []findingRow) string {
	base := normalizeCerebroContextJSON(raw)
	if a == nil || a.cerebroContextClient == nil || strings.TrimSpace(a.cerebroRuntimeID) == "" || len(findings) == 0 {
		return base
	}
	payload := cerebroContextMap(base)
	payload["source"] = "cerebro"
	payload["sourceRuntimeId"] = a.cerebroRuntimeID
	payload["findingContract"] = "cerebro.v1.Finding"

	claims, queriedClaims := a.saasCerebroIncidentClaims(ctx, findings)
	if len(claims) == 0 {
		if queriedClaims {
			resetSaasCerebroDerivedContext(payload)
		}
		return encodeCerebroContextMap(payload, base)
	}
	if len(claims) > maxSaasCerebroClaims {
		claims = claims[:maxSaasCerebroClaims]
	}

	entities := newCerebroEntityCollector()
	findingRoots := []string{}
	for _, claim := range claims {
		entities.addClaim(claim)
		if isCerebroFindingURN(claim.SubjectURN) && !containsString(findingRoots, claim.SubjectURN) {
			findingRoots = append(findingRoots, claim.SubjectURN)
		}
	}
	graphPaths := []map[string]any{}
	for _, rootURN := range boundedStrings(findingRoots, maxSaasCerebroGraphRoots) {
		neighborhood, err := a.cerebroContextClient.GetEntityNeighborhood(ctx, rootURN, maxSaasCerebroGraphLimit)
		if err != nil || neighborhood == nil {
			continue
		}
		entities.addNeighborhood(neighborhood)
		graphPaths = append(graphPaths, cerebroGraphPathsFromNeighborhood(neighborhood)...)
	}

	payload["mode"] = "claim-linked"
	if len(graphPaths) > 0 {
		payload["mode"] = "graph-linked"
	}
	payload["claimCount"] = len(claims)
	payload["claimSummaries"] = cerebroClaimSummaries(claims)
	payload["graphSignals"] = cerebroGraphSignals(claims)
	payload["entities"] = entities.items()
	payload["graphPaths"] = graphPaths
	payload["responseHints"] = []string{
		"Review Cerebro claims and graph paths before executing high-impact response actions.",
	}
	payload["mcp"] = map[string]any{
		"server":      "aperio-a2a-broker",
		"resourceUri": saasCerebroIncidentResourceURI(organizationID, incidentID),
		"mimeType":    "application/vnd.aperio.cerebro.incident+json",
		"tools":       saasCerebroMCPTools(),
	}
	return encodeCerebroContextMap(payload, base)
}

func (a *App) enrichAndPersistSaasCerebroContext(ctx context.Context, organizationID string, incidentID string, raw string, findings []findingRow) (string, error) {
	base := normalizeCerebroContextJSON(raw)
	enriched := a.enrichSaasCerebroContext(ctx, organizationID, incidentID, raw, findings)
	if a == nil || a.db == nil || enriched == base {
		return enriched, nil
	}
	if _, err := a.db.ExecContext(ctx, `
		UPDATE saas_incidents
		SET cerebro_context = $3::jsonb,
		    updated_at = NOW()
		WHERE organization_id = $1 AND id = $2
	`, organizationID, incidentID, enriched); err != nil {
		return "", internalServerError("saas_incident.cerebro_context.update", err)
	}
	return enriched, nil
}

func (a *App) saasCerebroIncidentClaims(ctx context.Context, findings []findingRow) ([]cerebroclient.Claim, bool) {
	claims := []cerebroclient.Claim{}
	queriedClaims := false
	seenEvents := map[string]struct{}{}
	for _, finding := range findings {
		sourceEventID := strings.TrimSpace(stringFromAny(finding.Evidence["sourceEventId"]))
		if sourceEventID == "" {
			continue
		}
		if _, ok := seenEvents[sourceEventID]; ok {
			continue
		}
		seenEvents[sourceEventID] = struct{}{}
		response, err := a.cerebroContextClient.ListClaims(ctx, cerebroclient.ListClaimsRequest{
			RuntimeID:     a.cerebroRuntimeID,
			Status:        "asserted",
			SourceEventID: sourceEventID,
			Limit:         50,
		})
		if err != nil || response == nil {
			continue
		}
		queriedClaims = true
		claims = append(claims, response.Claims...)
		if len(claims) >= maxSaasCerebroClaims || len(seenEvents) >= maxSaasCerebroClaimQueries {
			break
		}
	}
	return claims, queriedClaims
}

func resetSaasCerebroDerivedContext(payload map[string]any) {
	payload["mode"] = "context-pending"
	payload["claimCount"] = 0
	payload["claimSummaries"] = []map[string]any{}
	payload["graphSignals"] = []map[string]any{}
	payload["entities"] = []map[string]any{}
	payload["graphPaths"] = []map[string]any{}
	payload["responseHints"] = []string{
		"Attach Cerebro claims before executing high-impact response actions.",
	}
}

func cerebroContextMap(raw string) map[string]any {
	payload := map[string]any{}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil || payload == nil {
		return genericCerebroContextDefaults()
	}
	return payload
}

func encodeCerebroContextMap(payload map[string]any, fallback string) string {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fallback
	}
	return string(encoded)
}

func cerebroClaimSummaries(claims []cerebroclient.Claim) []map[string]any {
	summaries := make([]map[string]any, 0, minInt(len(claims), 8))
	seen := map[string]struct{}{}
	for _, claim := range claims {
		if strings.TrimSpace(claim.SubjectURN) == "" || strings.TrimSpace(claim.Predicate) == "" {
			continue
		}
		key := strings.Join([]string{claim.ClaimType, claim.Predicate, claim.SubjectURN, claim.ObjectURN, claim.SourceEventID}, "\x00")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		summaries = append(summaries, map[string]any{
			"claimType":   claim.ClaimType,
			"predicate":   claim.Predicate,
			"subjectUrn":  claim.SubjectURN,
			"objectUrn":   emptyToNil(claim.ObjectURN),
			"sourceEvent": emptyToNil(claim.SourceEventID),
		})
		if len(summaries) >= 8 {
			break
		}
	}
	return summaries
}

func cerebroGraphSignals(claims []cerebroclient.Claim) []map[string]any {
	signals := make([]map[string]any, 0, minInt(len(claims), 6))
	seen := map[string]struct{}{}
	for _, claim := range claims {
		evidence := firstString(claim.ObjectValue, claim.ObjectURN)
		if evidence == "" || strings.TrimSpace(claim.Predicate) == "" || strings.TrimSpace(claim.SubjectURN) == "" {
			continue
		}
		key := claim.Predicate + "\x00" + claim.SubjectURN + "\x00" + evidence
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		label := firstString(claim.SubjectRef.Label, shortCerebroURN(claim.SubjectURN))
		signals = append(signals, map[string]any{
			"label":      label,
			"predicate":  claim.Predicate,
			"confidence": 1,
			"entityUrn":  claim.SubjectURN,
			"evidence":   evidence,
		})
		if len(signals) >= 6 {
			break
		}
	}
	return signals
}

func cerebroGraphPathsFromNeighborhood(neighborhood *cerebroclient.EntityNeighborhood) []map[string]any {
	if neighborhood == nil || neighborhood.Root == nil {
		return nil
	}
	entityByURN := map[string]map[string]any{
		neighborhood.Root.URN: cerebroEntityMap(neighborhood.Root.URN, neighborhood.Root.EntityType, neighborhood.Root.Label),
	}
	for _, neighbor := range neighborhood.Neighbors {
		entityByURN[neighbor.URN] = cerebroEntityMap(neighbor.URN, neighbor.EntityType, neighbor.Label)
	}
	paths := []map[string]any{}
	for index, relation := range neighborhood.Relations {
		from := entityByURN[relation.FromURN]
		to := entityByURN[relation.ToURN]
		if from == nil || to == nil {
			continue
		}
		paths = append(paths, map[string]any{
			"id":    cerebroGraphPathID(index, relation),
			"title": relation.Relation,
			"risk":  "observed",
			"nodes": []map[string]any{from, to},
		})
		if len(paths) >= 5 {
			break
		}
	}
	return paths
}

func cerebroGraphPathID(index int, relation cerebroclient.GraphRelation) string {
	return fmt.Sprintf(
		"cerebro-path-%s-%s-%s-%d",
		cerebroGraphPathIDPart(relation.FromURN),
		cerebroGraphPathIDPart(relation.Relation),
		cerebroGraphPathIDPart(relation.ToURN),
		index+1,
	)
}

func cerebroGraphPathIDPart(value string) string {
	part := strings.ToLower(strings.TrimSpace(value))
	if part == "" {
		return "unknown"
	}
	part = strings.NewReplacer(
		":", "-",
		"/", "-",
		"\\", "-",
		" ", "-",
		"\t", "-",
		"\n", "-",
		".", "-",
		"@", "-",
	).Replace(part)
	for strings.Contains(part, "--") {
		part = strings.ReplaceAll(part, "--", "-")
	}
	part = strings.Trim(part, "-")
	if part == "" {
		return "unknown"
	}
	return part
}

type cerebroEntityCollector struct {
	order []string
	seen  map[string]map[string]any
}

func newCerebroEntityCollector() *cerebroEntityCollector {
	return &cerebroEntityCollector{seen: map[string]map[string]any{}}
}

func (c *cerebroEntityCollector) addClaim(claim cerebroclient.Claim) {
	c.addEntityRef(claim.SubjectRef)
	if claim.ObjectRef != nil {
		c.addEntityRef(*claim.ObjectRef)
	}
}

func (c *cerebroEntityCollector) addEntityRef(ref cerebroclient.EntityRef) {
	c.add(ref.URN, ref.EntityType, ref.Label)
}

func (c *cerebroEntityCollector) addNeighborhood(neighborhood *cerebroclient.EntityNeighborhood) {
	if neighborhood == nil {
		return
	}
	if neighborhood.Root != nil {
		c.add(neighborhood.Root.URN, neighborhood.Root.EntityType, neighborhood.Root.Label)
	}
	for _, neighbor := range neighborhood.Neighbors {
		c.add(neighbor.URN, neighbor.EntityType, neighbor.Label)
	}
}

func (c *cerebroEntityCollector) add(urn string, entityType string, label string) {
	urn = strings.TrimSpace(urn)
	if urn == "" {
		return
	}
	if _, ok := c.seen[urn]; ok {
		return
	}
	c.order = append(c.order, urn)
	c.seen[urn] = cerebroEntityMap(urn, entityType, label)
}

func (c *cerebroEntityCollector) items() []map[string]any {
	items := make([]map[string]any, 0, len(c.order))
	for _, urn := range c.order {
		items = append(items, c.seen[urn])
		if len(items) >= 12 {
			break
		}
	}
	return items
}

func cerebroEntityMap(urn string, entityType string, label string) map[string]any {
	return map[string]any{
		"urn":   urn,
		"type":  firstString(entityType, "entity"),
		"label": firstString(label, shortCerebroURN(urn), urn),
	}
}

func isCerebroFindingURN(urn string) bool {
	return strings.Contains(urn, ":finding:")
}

func shortCerebroURN(urn string) string {
	parts := strings.Split(strings.TrimSpace(urn), ":")
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			filtered = append(filtered, part)
		}
	}
	if len(filtered) >= 2 {
		return strings.Join(filtered[len(filtered)-2:], ":")
	}
	return strings.TrimSpace(urn)
}

func emptyToNil(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.TrimSpace(value)
}

func boundedStrings(values []string, limit int) []string {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
