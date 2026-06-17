package bootstrap

import (
	"context"
	"net/url"
	"strings"

	"github.com/writer/aperio/internal/cerebroclient"
)

const (
	maxSecurityCerebroClaimQueries = 12
	maxSecurityCerebroClaims       = 120
	maxSecurityCerebroGraphRoots   = 4
	maxSecurityCerebroGraphLimit   = 10
)

func (a *App) enrichSecurityOverviewCerebroContext(ctx context.Context, organizationID string, overview map[string]any, findings []overviewFinding) map[string]any {
	if overview == nil {
		overview = map[string]any{}
	}
	contextPayload := map[string]any{
		"source":          "local-projection",
		"mode":            "not-configured",
		"findingContract": "cerebro.v1.Finding",
		"responseHints": []string{
			"Configure Cerebro runtime access to link security graph rows to source-runtime claims.",
		},
	}
	if a == nil || a.cerebroContextClient == nil || strings.TrimSpace(a.cerebroRuntimeID) == "" {
		overview["cerebroContext"] = contextPayload
		return overview
	}

	contextPayload["source"] = "cerebro"
	contextPayload["mode"] = "runtime-configured"
	contextPayload["sourceRuntimeId"] = a.cerebroRuntimeID
	contextPayload["mcp"] = a.securityCerebroMCPContext(organizationID)
	contextPayload["responseHints"] = []string{
		"Use Cerebro claims and graph neighborhoods to validate high-blast-radius paths before response.",
	}

	claims := a.securityOverviewCerebroClaims(ctx, findings)
	if len(claims) == 0 {
		overview["cerebroContext"] = contextPayload
		return overview
	}
	if len(claims) > maxSecurityCerebroClaims {
		claims = claims[:maxSecurityCerebroClaims]
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
	graphPathCount := 0
	for _, rootURN := range boundedStrings(findingRoots, maxSecurityCerebroGraphRoots) {
		neighborhood, err := a.cerebroContextClient.GetEntityNeighborhood(ctx, rootURN, maxSecurityCerebroGraphLimit)
		if err != nil || neighborhood == nil {
			continue
		}
		entities.addNeighborhood(neighborhood)
		graphPathCount += cerebroGraphPathCountFromNeighborhood(neighborhood)
		graphPaths = append(graphPaths, cerebroGraphPathsFromNeighborhood(neighborhood)...)
	}
	contextPayload["mode"] = "claim-linked"
	if len(graphPaths) > 0 {
		contextPayload["mode"] = "graph-linked"
	}
	contextPayload["claimCount"] = len(claims)
	contextPayload["graphSignalCount"] = cerebroGraphSignalCount(claims)
	contextPayload["entityCount"] = entities.count()
	contextPayload["graphPathCount"] = graphPathCount
	overview["cerebroContext"] = contextPayload
	return overview
}

func (a *App) securityOverviewCerebroClaims(ctx context.Context, findings []overviewFinding) []cerebroclient.Claim {
	claims := []cerebroclient.Claim{}
	seenEvents := map[string]struct{}{}
	for _, finding := range findings {
		sourceEventID := strings.TrimSpace(finding.SourceEventID)
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
		claims = append(claims, response.Claims...)
		if len(claims) >= maxSecurityCerebroClaims || len(seenEvents) >= maxSecurityCerebroClaimQueries {
			break
		}
	}
	return claims
}

func (a *App) securityCerebroMCPContext(organizationID string) map[string]any {
	server := "aperio-a2a-broker"
	tools := []string{
		"aperio.list_cerebro_incidents",
	}
	resourceURI := "cerebro://aperio/" + url.PathEscape(strings.TrimSpace(organizationID)) + "/incidents"
	if a != nil && strings.TrimSpace(a.cerebroMCPServerURL) != "" {
		server = strings.TrimSpace(a.cerebroMCPServerURL)
		resourceURI = "cerebro://aperio/" + url.PathEscape(strings.TrimSpace(organizationID)) + "/security/overview"
		tools = []string{
			"cerebro.findings.search",
			"cerebro.graph.neighborhood",
			"cerebro.investigation.context",
			"cerebro.agent.preflight",
		}
	}
	return map[string]any{
		"server":      server,
		"resourceUri": resourceURI,
		"resource":    "cerebro-mcp",
		"tools":       tools,
	}
}
