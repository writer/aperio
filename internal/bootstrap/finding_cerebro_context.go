package bootstrap

import (
	"context"
	"net/url"
	"strings"

	aperiov1 "github.com/writer/aperio/gen/aperio/v1"
	cerebrov1 "github.com/writer/aperio/gen/cerebro/v1"
	"github.com/writer/aperio/internal/cerebroclient"
)

const (
	maxFindingCerebroClaims     = 50
	maxFindingCerebroGraphRoots = 2
	maxFindingCerebroGraphLimit = 12
)

func (a *App) enrichFindingCerebroContext(ctx context.Context, organizationID string, finding *findingRow) {
	if finding == nil {
		return
	}
	sourceEventID := strings.TrimSpace(stringFromAny(finding.Evidence["sourceEventId"]))
	contextPayload := &aperiov1.FindingCerebroContext{
		Source:          "local-projection",
		Mode:            "not-configured",
		FindingContract: "cerebro.v1.Finding",
		SourceEventId:   sourceEventID,
		ResponseHints: []string{
			"Configure Cerebro runtime access to link this finding to source-runtime claims.",
		},
	}
	if a == nil || a.cerebroContextClient == nil || strings.TrimSpace(a.cerebroRuntimeID) == "" {
		finding.CerebroContext = contextPayload
		return
	}

	contextPayload.Source = "cerebro"
	contextPayload.Mode = "runtime-configured"
	contextPayload.SourceRuntimeId = a.cerebroRuntimeID
	contextPayload.Mcp = a.findingCerebroMCPContext(organizationID, finding.ID)
	contextPayload.ResponseHints = []string{
		"Review Cerebro claims and graph paths before resolving or accepting this finding.",
	}
	if sourceEventID == "" {
		contextPayload.ResponseHints = []string{
			"Capture a sourceEventId on this finding to hydrate Cerebro source-runtime claims.",
		}
		finding.CerebroContext = contextPayload
		return
	}

	claims, err := a.findingCerebroClaims(ctx, sourceEventID)
	if err != nil {
		contextPayload.Mode = "context-pending"
		contextPayload.ClaimCount = 0
		contextPayload.ClaimSummaries = nil
		contextPayload.GraphSignals = nil
		contextPayload.Entities = nil
		contextPayload.GraphPaths = nil
		contextPayload.ResponseHints = []string{
			"Cerebro claim lookup is pending; retry after the runtime is reachable before treating this finding as unlinked.",
		}
		finding.CerebroContext = contextPayload
		return
	}
	if len(claims) == 0 {
		finding.CerebroContext = contextPayload
		return
	}
	if len(claims) > maxFindingCerebroClaims {
		claims = claims[:maxFindingCerebroClaims]
	}

	entities := newCerebroEntityCollector()
	findingRoots := []string{}
	for _, claim := range claims {
		entities.addClaim(claim)
		if subjectURN := claim.GetSubjectUrn(); isCerebroFindingURN(subjectURN) && !containsString(findingRoots, subjectURN) {
			findingRoots = append(findingRoots, subjectURN)
		}
	}

	graphPaths := []*aperiov1.CerebroGraphPath{}
	for _, rootURN := range boundedStrings(findingRoots, maxFindingCerebroGraphRoots) {
		neighborhood, err := a.cerebroContextClient.GetEntityNeighborhood(ctx, rootURN, maxFindingCerebroGraphLimit)
		if err != nil || neighborhood == nil {
			continue
		}
		entities.addNeighborhood(neighborhood)
		graphPaths = append(graphPaths, findingCerebroGraphPathsFromMaps(cerebroGraphPathsFromNeighborhood(neighborhood))...)
	}

	contextPayload.Mode = "claim-linked"
	if len(graphPaths) > 0 {
		contextPayload.Mode = "graph-linked"
	}
	contextPayload.ClaimCount = int32(len(claims))
	contextPayload.ClaimSummaries = findingCerebroClaimSummaries(claims)
	contextPayload.GraphSignals = findingCerebroGraphSignals(claims)
	contextPayload.Entities = findingCerebroEntitiesFromMaps(entities.items())
	contextPayload.GraphPaths = graphPaths
	finding.CerebroContext = contextPayload
}

func (a *App) findingCerebroClaims(ctx context.Context, sourceEventID string) ([]*cerebrov1.Claim, error) {
	if a == nil || a.cerebroContextClient == nil {
		return nil, nil
	}
	response, err := a.cerebroContextClient.ListProtoClaims(ctx, cerebroclient.ListClaimsRequest{
		RuntimeID:     a.cerebroRuntimeID,
		Status:        "asserted",
		SourceEventID: strings.TrimSpace(sourceEventID),
		Limit:         maxFindingCerebroClaims,
	})
	if err != nil || response == nil {
		if err == nil {
			err = context.Canceled
		}
		return nil, err
	}
	return response.Claims, nil
}

func (a *App) findingCerebroMCPContext(organizationID string, findingID string) *aperiov1.CerebroMCPContext {
	server := "aperio-a2a-broker"
	tools := saasCerebroMCPTools()
	if a != nil && strings.TrimSpace(a.cerebroMCPServerURL) != "" {
		server = strings.TrimSpace(a.cerebroMCPServerURL)
		tools = saasCerebroNativeMCPTools()
	}
	return &aperiov1.CerebroMCPContext{
		Server:            server,
		ResourceUri:       findingCerebroResourceURI(organizationID, findingID),
		MimeType:          "application/vnd.aperio.cerebro.finding+json",
		Tools:             tools,
		ResourceTemplates: cerebroMCPResourceTemplatesFromAny(saasCerebroMCPResourceTemplates()),
	}
}

func findingCerebroResourceURI(organizationID string, findingID string) string {
	return "cerebro://aperio/" + url.PathEscape(strings.TrimSpace(organizationID)) + "/findings/" + url.PathEscape(strings.TrimSpace(findingID))
}

func findingCerebroClaimSummaries(claims []*cerebrov1.Claim) []*aperiov1.CerebroClaimSummary {
	summaries := make([]*aperiov1.CerebroClaimSummary, 0, minInt(len(claims), 8))
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
		summaries = append(summaries, &aperiov1.CerebroClaimSummary{
			ClaimType:   claim.GetClaimType(),
			Predicate:   predicate,
			SubjectUrn:  subjectURN,
			ObjectUrn:   strings.TrimSpace(claim.GetObjectUrn()),
			SourceEvent: strings.TrimSpace(claim.GetSourceEventId()),
		})
		if len(summaries) >= 8 {
			break
		}
	}
	return summaries
}

func findingCerebroGraphSignals(claims []*cerebrov1.Claim) []*aperiov1.CerebroGraphSignal {
	signals := make([]*aperiov1.CerebroGraphSignal, 0, minInt(len(claims), 6))
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
		signals = append(signals, &aperiov1.CerebroGraphSignal{
			Label:      firstString(claim.GetSubjectRef().GetLabel(), shortCerebroURN(subjectURN)),
			Predicate:  predicate,
			Confidence: 1,
			EntityUrn:  subjectURN,
			Evidence:   evidence,
		})
		if len(signals) >= 6 {
			break
		}
	}
	return signals
}

func findingCerebroEntitiesFromMaps(items []map[string]any) []*aperiov1.CerebroEntityRef {
	out := make([]*aperiov1.CerebroEntityRef, 0, len(items))
	for _, item := range items {
		entity := findingCerebroEntityFromMap(item)
		if entity != nil {
			out = append(out, entity)
		}
	}
	return out
}

func findingCerebroGraphPathsFromMaps(items []map[string]any) []*aperiov1.CerebroGraphPath {
	out := make([]*aperiov1.CerebroGraphPath, 0, len(items))
	for _, item := range items {
		path := &aperiov1.CerebroGraphPath{
			Id:    stringFromAny(item["id"]),
			Title: stringFromAny(item["title"]),
			Risk:  stringFromAny(item["risk"]),
		}
		for _, rawNode := range anyList(item["nodes"]) {
			node := findingCerebroEntityFromMap(asMap(rawNode))
			if node != nil {
				path.Nodes = append(path.Nodes, node)
			}
		}
		if path.Id != "" && len(path.Nodes) > 0 {
			out = append(out, path)
		}
	}
	return out
}

func findingCerebroEntityFromMap(item map[string]any) *aperiov1.CerebroEntityRef {
	if len(item) == 0 {
		return nil
	}
	urn := stringFromAny(item["urn"])
	if strings.TrimSpace(urn) == "" {
		return nil
	}
	return &aperiov1.CerebroEntityRef{
		Urn:      urn,
		Type:     firstString(stringFromAny(item["type"]), "entity"),
		Label:    firstString(stringFromAny(item["label"]), shortCerebroURN(urn), urn),
		Provider: stringFromAny(item["provider"]),
	}
}
