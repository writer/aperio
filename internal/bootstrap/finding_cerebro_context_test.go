package bootstrap

import (
	"context"
	"errors"
	"testing"

	"github.com/writer/aperio/internal/cerebroclient"
)

func TestFindingCerebroContextReportsLocalProjectionWhenNotConfigured(t *testing.T) {
	finding := findingRow{
		ID:       "finding-1",
		Evidence: map[string]any{"sourceEventId": "evt-1"},
	}

	(&App{}).enrichFindingCerebroContext(context.Background(), "org-a", &finding)

	if finding.CerebroContext == nil {
		t.Fatal("expected Cerebro context")
	}
	if finding.CerebroContext.Source != "local-projection" || finding.CerebroContext.Mode != "not-configured" {
		t.Fatalf("unexpected local Cerebro context: %#v", finding.CerebroContext)
	}
	if finding.CerebroContext.SourceEventId != "evt-1" {
		t.Fatalf("source event = %q, want evt-1", finding.CerebroContext.SourceEventId)
	}
	proto := finding.toProto()
	if proto.CerebroContext == nil || proto.CerebroContext.FindingContract != "cerebro.v1.Finding" {
		t.Fatalf("proto Cerebro context = %#v", proto.CerebroContext)
	}
}

func TestFindingCerebroContextReportsPendingOnReadFailure(t *testing.T) {
	client := &fakeSaasCerebroContextClient{listErr: errors.New("cerebro unavailable")}
	app := (&App{}).WithCerebroContextClient("runtime-a", client)
	finding := findingRow{
		ID:       "finding-1",
		Evidence: map[string]any{"sourceEventId": "evt-1"},
	}

	app.enrichFindingCerebroContext(context.Background(), "org-a", &finding)

	contextPayload := finding.CerebroContext
	if contextPayload == nil {
		t.Fatal("expected Cerebro context")
	}
	if contextPayload.Mode != "context-pending" || contextPayload.SourceRuntimeId != "runtime-a" || contextPayload.ClaimCount != 0 {
		t.Fatalf("unexpected pending Cerebro context: %#v", contextPayload)
	}
	if len(contextPayload.ClaimSummaries) != 0 || len(contextPayload.GraphSignals) != 0 || len(contextPayload.Entities) != 0 || len(contextPayload.GraphPaths) != 0 {
		t.Fatalf("pending Cerebro context should keep derived collections empty: %#v", contextPayload)
	}
	if len(client.listRequests) != 1 || client.listRequests[0].SourceEventID != "evt-1" {
		t.Fatalf("list requests = %#v", client.listRequests)
	}
	proto := finding.toProto()
	if proto.CerebroContext == nil || proto.CerebroContext.Mode != "context-pending" || proto.CerebroContext.ClaimCount != 0 {
		t.Fatalf("proto pending Cerebro context = %#v", proto.CerebroContext)
	}
}

func TestFindingCerebroContextHydratesClaimsAndGraph(t *testing.T) {
	rootURN := "urn:cerebro:tenant-a:runtime:runtime-a:finding:finding-1"
	assetURN := "urn:cerebro:tenant-a:runtime:runtime-a:asset:drive"
	client := &fakeSaasCerebroContextClient{
		claims: map[string][]cerebroclient.Claim{
			"evt-1": {
				{
					SubjectURN:    rootURN,
					SubjectRef:    cerebroclient.EntityRef{URN: rootURN, EntityType: "finding", Label: "Drive exposure"},
					Predicate:     "severity",
					ObjectValue:   "HIGH",
					ClaimType:     "attribute",
					Status:        "asserted",
					SourceEventID: "evt-1",
				},
				{
					SubjectURN:    rootURN,
					SubjectRef:    cerebroclient.EntityRef{URN: rootURN, EntityType: "finding", Label: "Drive exposure"},
					Predicate:     "affects",
					ObjectURN:     assetURN,
					ObjectRef:     &cerebroclient.EntityRef{URN: assetURN, EntityType: "asset", Label: "Board Drive"},
					ClaimType:     "relation",
					Status:        "asserted",
					SourceEventID: "evt-1",
				},
			},
		},
		neighborhoods: map[string]*cerebroclient.EntityNeighborhood{
			rootURN: {
				Root:      &cerebroclient.GraphEntity{URN: rootURN, EntityType: "finding", Label: "Drive exposure"},
				Neighbors: []cerebroclient.GraphEntity{{URN: assetURN, EntityType: "asset", Label: "Board Drive"}},
				Relations: []cerebroclient.GraphRelation{{FromURN: rootURN, Relation: "affects", ToURN: assetURN}},
			},
		},
	}
	app := (&App{}).
		WithCerebroContextClient("runtime-a", client).
		WithCerebroMCPServerURL("https://cerebro.example.com/api/v1/mcp")
	finding := findingRow{
		ID:       "finding-1",
		Evidence: map[string]any{"sourceEventId": "evt-1"},
	}

	app.enrichFindingCerebroContext(context.Background(), "org-a", &finding)

	contextPayload := finding.CerebroContext
	if contextPayload == nil {
		t.Fatal("expected Cerebro context")
	}
	if contextPayload.Mode != "graph-linked" || contextPayload.SourceRuntimeId != "runtime-a" {
		t.Fatalf("unexpected linked Cerebro context: %#v", contextPayload)
	}
	if contextPayload.ClaimCount != 2 || len(contextPayload.Entities) != 2 || len(contextPayload.GraphPaths) != 1 {
		t.Fatalf("unexpected Cerebro counts: %#v", contextPayload)
	}
	if contextPayload.Mcp == nil || contextPayload.Mcp.Server != "https://cerebro.example.com/api/v1/mcp" || contextPayload.Mcp.ResourceUri != "cerebro://aperio/org-a/findings/finding-1" {
		t.Fatalf("unexpected Cerebro MCP context: %#v", contextPayload.Mcp)
	}
	if len(client.listRequests) != 1 || client.listRequests[0].SourceEventID != "evt-1" || client.listRequests[0].RuntimeID != "runtime-a" {
		t.Fatalf("list requests = %#v", client.listRequests)
	}
	proto := finding.toProto()
	if proto.CerebroContext == nil || proto.CerebroContext.ClaimCount != 2 || proto.CerebroContext.Mcp == nil {
		t.Fatalf("proto Cerebro context = %#v", proto.CerebroContext)
	}
}
