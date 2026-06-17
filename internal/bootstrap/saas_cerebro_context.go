package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/aperio/gen/cerebro/v1"
	"github.com/writer/aperio/internal/cerebroclient"
)

const (
	maxSaasCerebroClaimQueries = 8
	maxSaasCerebroClaims       = 80
	maxSaasCerebroGraphRoots   = 3
	maxSaasCerebroGraphLimit   = 12
)

type saasCerebroContextClient interface {
	ListProtoClaims(context.Context, cerebroclient.ListClaimsRequest) (*cerebroclient.ListProtoClaimsResponse, error)
	GetEntityNeighborhood(context.Context, string, uint32) (*cerebroclient.EntityNeighborhood, error)
}

func (a *App) WithCerebroContextClient(runtimeID string, client saasCerebroContextClient) *App {
	a.cerebroRuntimeID = strings.TrimSpace(runtimeID)
	a.cerebroContextClient = client
	return a
}

func (a *App) WithCerebroMCPServerURL(serverURL string) *App {
	a.cerebroMCPServerURL = strings.TrimSpace(serverURL)
	return a
}

func (a *App) enrichSaasCerebroContext(ctx context.Context, organizationID string, incidentID string, raw string, findings []findingRow) string {
	base := normalizeCerebroContextJSON(raw)
	if a == nil || a.cerebroContextClient == nil || strings.TrimSpace(a.cerebroRuntimeID) == "" {
		return base
	}
	payload := cerebroContextMap(base)
	payload["source"] = "cerebro"
	payload["sourceRuntimeId"] = a.cerebroRuntimeID
	payload["findingContract"] = "cerebro.v1.Finding"
	payload["mcp"] = a.saasCerebroMCPContext(organizationID, incidentID)

	if len(findings) == 0 {
		return encodeCerebroContextMap(payload, base)
	}
	claims := a.saasCerebroIncidentClaims(ctx, findings)
	if len(claims) == 0 {
		return encodeCerebroContextMap(payload, base)
	}
	if len(claims) > maxSaasCerebroClaims {
		claims = claims[:maxSaasCerebroClaims]
	}

	entities := newCerebroEntityCollector()
	findingRoots := []string{}
	for _, claim := range claims {
		entities.addClaim(claim)
		if subjectURN := claim.GetSubjectUrn(); isCerebroFindingURN(subjectURN) && !containsString(findingRoots, subjectURN) {
			findingRoots = append(findingRoots, subjectURN)
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
	return encodeCerebroContextMap(payload, base)
}

func (a *App) refreshSaasCerebroMCPContext(organizationID string, incidentID string, raw string) string {
	base := normalizeCerebroContextJSON(raw)
	payload := cerebroContextMap(base)
	if a != nil && strings.TrimSpace(a.cerebroRuntimeID) != "" {
		payload["sourceRuntimeId"] = strings.TrimSpace(a.cerebroRuntimeID)
	}
	payload["mcp"] = a.saasCerebroMCPContext(organizationID, incidentID)
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

func (a *App) saasCerebroIncidentClaims(ctx context.Context, findings []findingRow) []*cerebrov1.Claim {
	claims := []*cerebrov1.Claim{}
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
		response, err := a.cerebroContextClient.ListProtoClaims(ctx, cerebroclient.ListClaimsRequest{
			RuntimeID:     a.cerebroRuntimeID,
			Status:        "asserted",
			SourceEventID: sourceEventID,
			Limit:         50,
		})
		if err != nil || response == nil {
			continue
		}
		claims = append(claims, response.Claims...)
		if len(claims) >= maxSaasCerebroClaims || len(seenEvents) >= maxSaasCerebroClaimQueries {
			break
		}
	}
	return claims
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

func cerebroClaimSummaries(claims []*cerebrov1.Claim) []map[string]any {
	summaries := make([]map[string]any, 0, minInt(len(claims), 8))
	seen := map[string]struct{}{}
	for _, claim := range claims {
		subjectURN := claim.GetSubjectUrn()
		predicate := claim.GetPredicate()
		if strings.TrimSpace(subjectURN) == "" || strings.TrimSpace(predicate) == "" {
			continue
		}
		key := strings.Join([]string{claim.GetClaimType(), predicate, subjectURN, claim.GetObjectUrn(), claim.GetSourceEventId()}, "\x00")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		summaries = append(summaries, map[string]any{
			"claimType":   claim.GetClaimType(),
			"predicate":   predicate,
			"subjectUrn":  subjectURN,
			"objectUrn":   emptyToNil(claim.GetObjectUrn()),
			"sourceEvent": emptyToNil(claim.GetSourceEventId()),
		})
		if len(summaries) >= 8 {
			break
		}
	}
	return summaries
}

func cerebroGraphSignals(claims []*cerebrov1.Claim) []map[string]any {
	signals := make([]map[string]any, 0, minInt(len(claims), 6))
	seen := map[string]struct{}{}
	for _, claim := range claims {
		subjectURN := claim.GetSubjectUrn()
		predicate := claim.GetPredicate()
		evidence := firstString(claim.GetObjectValue(), claim.GetObjectUrn())
		if evidence == "" || strings.TrimSpace(predicate) == "" || strings.TrimSpace(subjectURN) == "" {
			continue
		}
		key := predicate + "\x00" + subjectURN + "\x00" + evidence
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		label := firstString(claim.GetSubjectRef().GetLabel(), shortCerebroURN(subjectURN))
		signals = append(signals, map[string]any{
			"label":      label,
			"predicate":  predicate,
			"confidence": 1,
			"entityUrn":  subjectURN,
			"evidence":   evidence,
		})
		if len(signals) >= 6 {
			break
		}
	}
	return signals
}

func cerebroGraphSignalCount(claims []*cerebrov1.Claim) int {
	seen := map[string]struct{}{}
	for _, claim := range claims {
		subjectURN := claim.GetSubjectUrn()
		predicate := claim.GetPredicate()
		evidence := firstString(claim.GetObjectValue(), claim.GetObjectUrn())
		if evidence == "" || strings.TrimSpace(predicate) == "" || strings.TrimSpace(subjectURN) == "" {
			continue
		}
		key := predicate + "\x00" + subjectURN + "\x00" + evidence
		seen[key] = struct{}{}
	}
	return len(seen)
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

func cerebroGraphPathCountFromNeighborhood(neighborhood *cerebroclient.EntityNeighborhood) int {
	if neighborhood == nil || neighborhood.Root == nil {
		return 0
	}
	entityByURN := map[string]struct{}{
		neighborhood.Root.URN: {},
	}
	for _, neighbor := range neighborhood.Neighbors {
		entityByURN[neighbor.URN] = struct{}{}
	}
	count := 0
	for _, relation := range neighborhood.Relations {
		if _, ok := entityByURN[relation.FromURN]; !ok {
			continue
		}
		if _, ok := entityByURN[relation.ToURN]; !ok {
			continue
		}
		count++
	}
	return count
}

type cerebroEntityCollector struct {
	order []string
	seen  map[string]map[string]any
}

func newCerebroEntityCollector() *cerebroEntityCollector {
	return &cerebroEntityCollector{seen: map[string]map[string]any{}}
}

func (c *cerebroEntityCollector) addClaim(claim *cerebrov1.Claim) {
	if claim == nil {
		return
	}
	c.addProtoEntityRef(claim.GetSubjectRef())
	if claim.GetObjectRef() != nil {
		c.addProtoEntityRef(claim.GetObjectRef())
	}
}

func (c *cerebroEntityCollector) addProtoEntityRef(ref *cerebrov1.EntityRef) {
	if ref == nil {
		return
	}
	c.add(ref.GetUrn(), ref.GetEntityType(), ref.GetLabel())
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

func (c *cerebroEntityCollector) count() int {
	if c == nil {
		return 0
	}
	return len(c.order)
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

func (a *App) saasCerebroMCPContext(organizationID string, incidentID string) map[string]any {
	server := "aperio-a2a-broker"
	tools := saasCerebroMCPTools()
	if a != nil && strings.TrimSpace(a.cerebroMCPServerURL) != "" {
		server = strings.TrimSpace(a.cerebroMCPServerURL)
		tools = saasCerebroNativeMCPTools()
	}
	return map[string]any{
		"server":            server,
		"resourceUri":       saasCerebroIncidentResourceURI(organizationID, incidentID),
		"mimeType":          "application/vnd.aperio.cerebro.incident+json",
		"tools":             tools,
		"resourceTemplates": saasCerebroMCPResourceTemplates(),
	}
}

func saasCerebroMCPResourceTemplates() []map[string]string {
	return []map[string]string{
		{
			"uriTemplate": "cerebro://aperio/{organizationId}/incidents/{incidentId}",
			"name":        "Aperio Cerebro incident",
			"description": "Tenant-scoped Cerebro graph context for a SaaS incident in Aperio.",
			"mimeType":    "application/vnd.aperio.cerebro.incident+json",
		},
		{
			"uriTemplate": "cerebro://aperio/{organizationId}/findings/{findingId}",
			"name":        "Aperio Cerebro finding",
			"description": "Tenant-scoped Cerebro finding context with evidence, incident links, and response actions.",
			"mimeType":    "application/vnd.aperio.cerebro.finding+json",
		},
		{
			"uriTemplate": "cerebro://aperio/{organizationId}/security/overview",
			"name":        "Aperio Cerebro security overview",
			"description": "Tenant-scoped Cerebro security posture overview with linked incident and finding resources.",
			"mimeType":    "application/vnd.aperio.cerebro.security-overview+json",
		},
	}
}

func saasCerebroNativeMCPTools() []string {
	return []string{
		"cerebro.findings.list",
		"cerebro.findings.get",
		"cerebro.findings.search",
		"cerebro.risk.summary",
		"cerebro.risk.actions.list",
		"cerebro.risk.actions.explain",
		"cerebro.graph.neighborhood",
		"cerebro.graph.impact",
		"cerebro.graph.paths",
		"cerebro.investigation.context",
		"cerebro.findings.action.propose",
		"cerebro.agent.preflight",
	}
}
