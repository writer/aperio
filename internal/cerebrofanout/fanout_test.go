package cerebrofanout

import (
	"context"
	"errors"
	"testing"

	"github.com/writer/aperio/internal/cerebroclient"
)

type recordingWriter struct {
	requests []cerebroclient.WriteClaimsRequest
	response *cerebroclient.WriteClaimsResponse
	err      error
}

func (w *recordingWriter) WriteClaims(_ context.Context, request cerebroclient.WriteClaimsRequest) (*cerebroclient.WriteClaimsResponse, error) {
	w.requests = append(w.requests, request)
	if w.err != nil {
		return nil, w.err
	}
	if w.response != nil {
		return w.response, nil
	}
	return &cerebroclient.WriteClaimsResponse{ClaimsWritten: uint32(len(request.Claims))}, nil
}

func TestFanoutFindingWritesTenantScopedClaims(t *testing.T) {
	writer := &recordingWriter{response: &cerebroclient.WriteClaimsResponse{
		ClaimsWritten:          9,
		EntitiesUpserted:       3,
		RelationLinksProjected: 2,
	}}
	service, err := New(cerebroclient.Config{
		TenantID:  "cerebro-tenant",
		RuntimeID: "runtime-a",
	}, writer)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	result, err := service.FanoutFinding(context.Background(), FindingPayload{
		OrganizationID: "aperio-org",
		Kind:           "finding",
		OccurredAt:     "2026-06-16T12:00:00Z",
		Record: map[string]any{
			"findingId":     "fnd-1",
			"dedupeKey":     "dedupe-1",
			"sourceEventId": "evt-1",
			"title":         "Public repository created",
			"provider":      "GITHUB",
			"target":        "payments-service",
			"riskScore":     float64(91),
		},
	})
	if err != nil {
		t.Fatalf("FanoutFinding() error = %v", err)
	}
	if result.TenantID != "cerebro-tenant" || result.RuntimeID != "runtime-a" || result.FindingID != "fnd-1" || result.DedupeKey != "dedupe-1" || result.SourceEventID != "evt-1" {
		t.Fatalf("result metadata = %#v", result)
	}
	if result.ClaimsWritten != 9 || result.EntitiesUpserted != 3 || result.RelationLinksProjected != 2 {
		t.Fatalf("result counts = %#v", result)
	}
	if len(writer.requests) != 1 {
		t.Fatalf("requests = %d, want 1", len(writer.requests))
	}
	request := writer.requests[0]
	if request.RuntimeID != "runtime-a" {
		t.Fatalf("RuntimeID = %q", request.RuntimeID)
	}
	if len(request.Claims) != result.ClaimCount {
		t.Fatalf("request claim count = %d, result = %d", len(request.Claims), result.ClaimCount)
	}
	if got := request.Claims[0].SubjectURN; got != "urn:cerebro:cerebro-tenant:runtime:runtime-a:finding:dedupe-1" {
		t.Fatalf("SubjectURN = %q", got)
	}
	if got := request.Claims[0].Attributes["aperio_schema"]; got != "aperio/finding/v1" {
		t.Fatalf("aperio_schema = %q", got)
	}
}

func TestNewRejectsMissingTenantOrWriter(t *testing.T) {
	if _, err := New(cerebroclient.Config{TenantID: "tenant-a"}, nil); err == nil {
		t.Fatal("New(nil writer) error = nil")
	}
	if _, err := New(cerebroclient.Config{}, &recordingWriter{}); err == nil {
		t.Fatal("New(missing tenant) error = nil")
	}
}

func TestFanoutFindingReturnsPartialMetadataOnWriteFailure(t *testing.T) {
	wantErr := errors.New("cerebro unavailable")
	service, err := New(cerebroclient.Config{TenantID: "tenant-a", RuntimeID: "runtime-a"}, &recordingWriter{err: wantErr})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	result, err := service.FanoutFinding(context.Background(), FindingPayload{
		OrganizationID: "org-a",
		Kind:           "finding",
		OccurredAt:     "2026-06-16T12:00:00Z",
		Record: map[string]any{
			"dedupeKey":     "dedupe-a",
			"sourceEventId": "evt-a",
		},
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("FanoutFinding() error = %v, want %v", err, wantErr)
	}
	if result.RuntimeID != "runtime-a" || result.DedupeKey != "dedupe-a" || result.SourceEventID != "evt-a" || result.ClaimCount == 0 {
		t.Fatalf("partial result = %#v", result)
	}
}
