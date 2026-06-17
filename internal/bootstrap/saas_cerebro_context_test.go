package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/writer/aperio/internal/cerebroclient"
)

type fakeSaasCerebroContextClient struct {
	claims        map[string][]cerebroclient.Claim
	neighborhoods map[string]*cerebroclient.EntityNeighborhood
	listErr       error
	graphErr      error
	listRequests  []cerebroclient.ListClaimsRequest
	graphRoots    []string
}

func (c *fakeSaasCerebroContextClient) ListClaims(_ context.Context, request cerebroclient.ListClaimsRequest) (*cerebroclient.ListClaimsResponse, error) {
	c.listRequests = append(c.listRequests, request)
	if c.listErr != nil {
		return nil, c.listErr
	}
	return &cerebroclient.ListClaimsResponse{Claims: c.claims[request.SourceEventID]}, nil
}

func (c *fakeSaasCerebroContextClient) GetEntityNeighborhood(_ context.Context, rootURN string, _ uint32) (*cerebroclient.EntityNeighborhood, error) {
	c.graphRoots = append(c.graphRoots, rootURN)
	if c.graphErr != nil {
		return nil, c.graphErr
	}
	return c.neighborhoods[rootURN], nil
}

func TestEnrichSaasCerebroContextHydratesClaimsAndGraph(t *testing.T) {
	rootURN := "urn:cerebro:tenant-a:runtime:runtime-a:finding:dedupe-a"
	assetURN := "urn:cerebro:tenant-a:runtime:runtime-a:asset:GITHUB%3Awriter%2Faperio"
	client := &fakeSaasCerebroContextClient{
		claims: map[string][]cerebroclient.Claim{
			"evt-a": {
				{
					SubjectURN: rootURN,
					SubjectRef: cerebroclient.EntityRef{URN: rootURN, EntityType: "finding", Label: "Public repository created"},
					Predicate:  "exists",
					ClaimType:  "existence",
					Status:     "asserted",
				},
				{
					SubjectURN:    rootURN,
					SubjectRef:    cerebroclient.EntityRef{URN: rootURN, EntityType: "finding", Label: "Public repository created"},
					Predicate:     "severity",
					ObjectValue:   "HIGH",
					ClaimType:     "attribute",
					Status:        "asserted",
					SourceEventID: "evt-a",
				},
				{
					SubjectURN:    rootURN,
					SubjectRef:    cerebroclient.EntityRef{URN: rootURN, EntityType: "finding", Label: "Public repository created"},
					Predicate:     "affects",
					ObjectURN:     assetURN,
					ObjectRef:     &cerebroclient.EntityRef{URN: assetURN, EntityType: "asset", Label: "writer/aperio"},
					ClaimType:     "relation",
					Status:        "asserted",
					SourceEventID: "evt-a",
				},
			},
		},
		neighborhoods: map[string]*cerebroclient.EntityNeighborhood{
			rootURN: {
				Root: &cerebroclient.GraphEntity{URN: rootURN, EntityType: "finding", Label: "Public repository created"},
				Neighbors: []cerebroclient.GraphEntity{
					{URN: assetURN, EntityType: "asset", Label: "writer/aperio"},
				},
				Relations: []cerebroclient.GraphRelation{
					{FromURN: rootURN, Relation: "affects", ToURN: assetURN},
				},
			},
		},
	}
	app := (&App{}).
		WithCerebroContextClient("runtime-a", client).
		WithCerebroMCPServerURL("https://cerebro.example.com/api/v1/mcp")

	encoded := app.enrichSaasCerebroContext(context.Background(), "org-a", "inc-a", saasCerebroContextJSON("org-a", "inc-a"), []findingRow{
		{Evidence: map[string]any{"sourceEventId": "evt-a"}},
	})
	contextPayload := decodeSaasCerebroContext(t, encoded)
	if contextPayload["mode"] != "graph-linked" || contextPayload["sourceRuntimeId"] != "runtime-a" || contextPayload["claimCount"] != float64(3) {
		t.Fatalf("context payload = %#v", contextPayload)
	}
	if len(client.listRequests) != 1 || client.listRequests[0].RuntimeID != "runtime-a" || client.listRequests[0].SourceEventID != "evt-a" || client.listRequests[0].Status != "asserted" {
		t.Fatalf("list requests = %#v", client.listRequests)
	}
	if len(client.graphRoots) != 1 || client.graphRoots[0] != rootURN {
		t.Fatalf("graph roots = %#v", client.graphRoots)
	}
	if got := len(contextRecords(contextPayload["claimSummaries"])); got != 3 {
		t.Fatalf("claim summaries = %d", got)
	}
	if got := len(contextRecords(contextPayload["entities"])); got != 2 {
		t.Fatalf("entities = %d", got)
	}
	if got := len(contextRecords(contextPayload["graphSignals"])); got != 2 {
		t.Fatalf("graph signals = %d", got)
	}
	if got := len(contextRecords(contextPayload["graphPaths"])); got != 1 {
		t.Fatalf("graph paths = %d", got)
	}
	mcp := contextRecord(contextPayload["mcp"])
	if mcp["server"] != "https://cerebro.example.com/api/v1/mcp" || mcp["resourceUri"] != "cerebro://aperio/org-a/incidents/inc-a" {
		t.Fatalf("mcp context = %#v", mcp)
	}
	tools := contextRecords(mcp["tools"])
	if len(tools) != 4 || tools[1] != "cerebro.graph.neighborhood" {
		t.Fatalf("mcp tools = %#v", tools)
	}
}

func TestCerebroGraphPathsUseEndpointStableIDs(t *testing.T) {
	assetURN := "urn:cerebro:tenant-a:runtime:runtime-a:asset:GITHUB%3Awriter%2Faperio"
	firstRootURN := "urn:cerebro:tenant-a:runtime:runtime-a:finding:dedupe-a"
	secondRootURN := "urn:cerebro:tenant-a:runtime:runtime-a:finding:dedupe-b"
	firstPaths := cerebroGraphPathsFromNeighborhood(&cerebroclient.EntityNeighborhood{
		Root: &cerebroclient.GraphEntity{URN: firstRootURN, EntityType: "finding", Label: "Finding A"},
		Neighbors: []cerebroclient.GraphEntity{
			{URN: assetURN, EntityType: "asset", Label: "writer/aperio"},
		},
		Relations: []cerebroclient.GraphRelation{
			{FromURN: firstRootURN, Relation: "affects", ToURN: assetURN},
		},
	})
	secondPaths := cerebroGraphPathsFromNeighborhood(&cerebroclient.EntityNeighborhood{
		Root: &cerebroclient.GraphEntity{URN: secondRootURN, EntityType: "finding", Label: "Finding B"},
		Neighbors: []cerebroclient.GraphEntity{
			{URN: assetURN, EntityType: "asset", Label: "writer/aperio"},
		},
		Relations: []cerebroclient.GraphRelation{
			{FromURN: secondRootURN, Relation: "affects", ToURN: assetURN},
		},
	})
	if len(firstPaths) != 1 || len(secondPaths) != 1 {
		t.Fatalf("paths = %#v %#v", firstPaths, secondPaths)
	}
	if firstPaths[0]["id"] == secondPaths[0]["id"] {
		t.Fatalf("graph path ids must be unique across neighborhoods: %#v", firstPaths[0]["id"])
	}
	if firstPaths[0]["id"] == "cerebro-path-1-affects" || secondPaths[0]["id"] == "cerebro-path-1-affects" {
		t.Fatalf("graph path id does not include relation endpoints: %#v %#v", firstPaths[0]["id"], secondPaths[0]["id"])
	}
}

func TestEnrichSaasCerebroContextKeepsSafeFallbackOnReadFailure(t *testing.T) {
	client := &fakeSaasCerebroContextClient{listErr: errors.New("cerebro unavailable")}
	app := (&App{}).WithCerebroContextClient("runtime-a", client)

	encoded := app.enrichSaasCerebroContext(context.Background(), "org-a", "inc-a", "{}", []findingRow{
		{Evidence: map[string]any{"sourceEventId": "evt-a"}},
	})
	contextPayload := decodeSaasCerebroContext(t, encoded)
	if contextPayload["mode"] != "context-pending" || contextPayload["sourceRuntimeId"] != "runtime-a" || contextPayload["claimCount"] != float64(0) {
		t.Fatalf("fallback context = %#v", contextPayload)
	}
	if got := len(contextRecords(contextPayload["claimSummaries"])); got != 0 {
		t.Fatalf("fallback claim summaries = %d", got)
	}
}

func TestEnrichSaasCerebroContextUpdatesMCPBeforeClaimHydration(t *testing.T) {
	client := &fakeSaasCerebroContextClient{}
	app := (&App{}).
		WithCerebroContextClient("runtime-a", client).
		WithCerebroMCPServerURL("https://cerebro.example.com/api/v1/mcp")

	encoded := app.enrichSaasCerebroContext(context.Background(), "org-a", "inc-a", "{}", []findingRow{
		{Evidence: map[string]any{"sourceEventId": "evt-a"}},
	})
	contextPayload := decodeSaasCerebroContext(t, encoded)
	mcp := contextRecord(contextPayload["mcp"])
	if mcp["server"] != "https://cerebro.example.com/api/v1/mcp" || mcp["resourceUri"] != "cerebro://aperio/org-a/incidents/inc-a" {
		t.Fatalf("mcp context = %#v", mcp)
	}
	tools := contextRecords(mcp["tools"])
	if len(tools) != 4 || tools[0] != "cerebro.findings.search" {
		t.Fatalf("mcp tools = %#v", tools)
	}
}

func decodeSaasCerebroContext(t *testing.T, encoded string) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal([]byte(encoded), &payload); err != nil {
		t.Fatalf("decode Cerebro context: %v", err)
	}
	return payload
}

func contextRecord(value any) map[string]any {
	record, _ := value.(map[string]any)
	return record
}

func contextRecords(value any) []any {
	records, _ := value.([]any)
	return records
}
