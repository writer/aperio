package cerebroclaims

import (
	"testing"

	"github.com/writer/aperio/internal/cerebroclient"
)

func TestBuildCreatesFindingAssetAndIntegrationClaims(t *testing.T) {
	claims, err := Build(BuildInput{
		OrganizationID: "org_123",
		RuntimeID:      "runtime-main",
		Payload: Payload{
			Kind:       "FINDING_CREATED",
			OccurredAt: "2026-06-16T12:00:00Z",
			Record: map[string]any{
				"provider":      "GITHUB",
				"title":         "Public repository created",
				"target":        "payments-service",
				"integrationId": "int_github",
				"dedupeKey":     "dedupe-123",
				"sourceEventId": "evt-123",
				"severity":      "HIGH",
				"riskScore":     float64(91),
			},
		},
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if len(claims) != 9 {
		t.Fatalf("len(claims) = %d, want 9", len(claims))
	}
	if !hasClaim(claims, "existence", "exists", "") {
		t.Fatal("missing existence claim")
	}
	if !hasClaim(claims, "relation", "affects", "") {
		t.Fatal("missing affects relation claim")
	}
	if !hasClaim(claims, "attribute", "riskScore", "91") {
		t.Fatal("missing normalized numeric risk score claim")
	}
	if claims[0].SourceEventID != "evt-123" {
		t.Fatalf("SourceEventID = %q", claims[0].SourceEventID)
	}
	if got := claims[0].Attributes["aperio_schema"]; got != "aperio/finding/v1" {
		t.Fatalf("aperio_schema = %q", got)
	}
}

func TestRefEncodesExternalIDLikeCerebroURNPathSegment(t *testing.T) {
	ref := Ref(
		"org_urn_encoding",
		"runtime-main",
		"finding",
		"finding:id with spaces!*'()~:/?#[]@é",
		"Encoded finding",
	)
	want := "urn:cerebro:org_urn_encoding:runtime:runtime-main:finding:finding%3Aid-with-spaces!*'()~%3A%2F%3F%23%5B%5D%40%C3%A9"
	if ref.URN != want {
		t.Fatalf("URN = %q, want %q", ref.URN, want)
	}
}

func TestBuildUsesExplicitCerebroTenantForURNs(t *testing.T) {
	claims, err := Build(BuildInput{
		TenantID:       "cerebro-tenant",
		OrganizationID: "aperio-org",
		RuntimeID:      "runtime-main",
		Payload: Payload{
			Kind:       "finding",
			OccurredAt: "2026-06-16T12:00:00Z",
			Record: map[string]any{
				"title":         "Tenant mapped finding",
				"dedupeKey":     "dedupe-tenant",
				"sourceEventId": "evt-tenant",
			},
		},
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if len(claims) == 0 {
		t.Fatal("Build() returned no claims")
	}
	if got := claims[0].SubjectURN; got != "urn:cerebro:cerebro-tenant:runtime:runtime-main:finding:dedupe-tenant" {
		t.Fatalf("SubjectURN = %q", got)
	}
}

func hasClaim(claims []cerebroclient.Claim, claimType string, predicate string, objectValue string) bool {
	for _, claim := range claims {
		if claim.ClaimType == claimType && claim.Predicate == predicate {
			if objectValue == "" || claim.ObjectValue == objectValue {
				return true
			}
		}
	}
	return false
}
