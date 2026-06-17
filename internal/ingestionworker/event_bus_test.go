package ingestionworker

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	aperiocontractsv1 "github.com/writer/aperio/gen/aperio/contracts/v1"
	cerebrov1 "github.com/writer/cerebro/sdk/go/cerebroapi/genproto/cerebro/v1"
	"google.golang.org/protobuf/proto"
)

func TestEncodeIngestionJobLifecycleEventMatchesCerebroEnvelope(t *testing.T) {
	occurredAt := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	encoded, err := encodeIngestionJobLifecycleEvent(IngestionJobLifecycleEvent{
		JobID:          "job_123",
		OrganizationID: "org_123",
		IntegrationID:  "int_123",
		Provider:       "GITHUB",
		EventType:      "PUBLIC_REPOSITORY_CREATED",
		Source:         "github.audit",
		Actor:          "owner@example.test",
		Status:         "succeeded",
		Attempts:       2,
		SourceEventID:  "evt_source_123",
		OccurredAt:     occurredAt,
		Payload:        json.RawMessage(`{"repository":{"full_name":"writer/aperio"}}`),
	})
	if err != nil {
		t.Fatalf("encode ingestion job lifecycle event: %v", err)
	}
	if encoded.id == "" || encoded.subject != "events.aperio.ingestion_job.succeeded" || len(encoded.payload) == 0 {
		t.Fatalf("unexpected encoded event metadata: %#v", encoded)
	}
	var envelope cerebrov1.EventEnvelope
	if err := proto.Unmarshal(encoded.payload, &envelope); err != nil {
		t.Fatalf("decode ingestion envelope: %v", err)
	}
	if envelope.GetTenantId() != "org_123" || envelope.GetSourceId() != "aperio" || envelope.GetKind() != "aperio.ingestion_job.succeeded" || envelope.GetSchemaRef() != ingestionJobSchemaRef {
		t.Fatalf("unexpected ingestion envelope: %#v", &envelope)
	}
	if envelope.GetAttributes()["job_id"] != "job_123" || envelope.GetAttributes()["source_event_id"] != "evt_source_123" {
		t.Fatalf("ingestion envelope attributes = %#v", envelope.GetAttributes())
	}
	var payload aperiocontractsv1.IngestionJobEvent
	if err := proto.Unmarshal(envelope.GetPayload(), &payload); err != nil {
		t.Fatalf("decode ingestion domain payload: %v", err)
	}
	if payload.GetJobId() != "job_123" || payload.GetStatus() != "succeeded" || payload.GetAttempts() != 2 || payload.GetSourceEventId() != "evt_source_123" {
		t.Fatalf("unexpected ingestion payload: %#v", &payload)
	}
	if !json.Valid(payload.GetPayloadJson()) || string(payload.GetPayloadJson()) == "{}" {
		t.Fatalf("ingestion payload JSON was not preserved: %s", string(payload.GetPayloadJson()))
	}

	encoded, err = encodeIngestionJobLifecycleEvent(IngestionJobLifecycleEvent{
		JobID:          "job_bad_payload",
		OrganizationID: "org_123",
		IntegrationID:  "int_123",
		Provider:       "SLACK",
		EventType:      "MFA_DISABLED",
		Source:         "slack.audit",
		Status:         "failed",
		Attempts:       1,
		OccurredAt:     occurredAt,
		Payload:        json.RawMessage(`[]`),
	})
	if err != nil {
		t.Fatalf("encode non-object payload event: %v", err)
	}
	if err := proto.Unmarshal(encoded.payload, &envelope); err != nil {
		t.Fatalf("decode non-object envelope: %v", err)
	}
	if err := proto.Unmarshal(envelope.GetPayload(), &payload); err != nil {
		t.Fatalf("decode non-object domain payload: %v", err)
	}
	if string(payload.GetPayloadJson()) != "{}" {
		t.Fatalf("non-object job lifecycle payload should be redacted to an object, got %s", string(payload.GetPayloadJson()))
	}
}

func TestEncodeFindingLifecycleEventUsesSystemStatusEnvelope(t *testing.T) {
	encoded, err := encodeFindingLifecycleEvent(FindingLifecycleEvent{
		FindingID:      "fnd_123",
		OrganizationID: "org_123",
		IntegrationID:  "int_123",
		PreviousStatus: "RESOLVED",
		NextStatus:     "OPEN",
		OccurredAt:     time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC),
		ResolutionNote: "Finding observed again during ingestion",
	})
	if err != nil {
		t.Fatalf("encode finding lifecycle event: %v", err)
	}
	if encoded.subject != "events.aperio.finding.reopened" {
		t.Fatalf("finding lifecycle subject = %s", encoded.subject)
	}
	var envelope cerebrov1.EventEnvelope
	if err := proto.Unmarshal(encoded.payload, &envelope); err != nil {
		t.Fatalf("decode finding envelope: %v", err)
	}
	if envelope.GetKind() != "aperio.finding.reopened" || envelope.GetSchemaRef() != findingLifecycleSchemaRef || envelope.GetAttributes()["status_source"] != "system" {
		t.Fatalf("unexpected finding envelope: %#v attrs=%#v", &envelope, envelope.GetAttributes())
	}
	var payload aperiocontractsv1.FindingLifecycleEvent
	if err := proto.Unmarshal(envelope.GetPayload(), &payload); err != nil {
		t.Fatalf("decode finding domain payload: %v", err)
	}
	if payload.GetFindingId() != "fnd_123" || payload.GetPreviousStatus() != "RESOLVED" || payload.GetNextStatus() != "OPEN" || payload.GetStatusSource() != "system" {
		t.Fatalf("unexpected finding payload: %#v", &payload)
	}
}

func TestNATSEventPublisherPublishesWhenEnabled(t *testing.T) {
	natsURL := strings.TrimSpace(os.Getenv("APERIO_TEST_NATS_URL"))
	if natsURL == "" {
		t.Skip("set APERIO_TEST_NATS_URL to run local NATS ingestion event publisher test")
	}
	nc, err := nats.Connect(natsURL, nats.Timeout(2*time.Second))
	if err != nil {
		t.Fatalf("connect test NATS: %v", err)
	}
	defer nc.Close()
	subject := "events.aperio.ingestion_job.succeeded"
	sub, err := nc.SubscribeSync(subject)
	if err != nil {
		t.Fatalf("subscribe test NATS subject: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush NATS subscription: %v", err)
	}

	t.Setenv("APERIO_EVENT_BUS", "nats")
	t.Setenv("APERIO_NATS_URL", natsURL)
	t.Setenv("APERIO_NATS_STREAM", "CEREBRO_EVENTS_TEST_"+randomID())
	publisher := NewEnvEventPublisher()
	if _, ok := publisher.(*natsIngestionEventPublisher); !ok {
		t.Fatalf("expected NATS publisher when APERIO_EVENT_BUS=nats, got %T", publisher)
	}

	err = publisher.PublishIngestionJobLifecycle(context.Background(), IngestionJobLifecycleEvent{
		JobID:          "job_nats_123",
		OrganizationID: "org_nats_123",
		IntegrationID:  "int_nats_123",
		Provider:       "GITHUB",
		EventType:      "PUBLIC_REPOSITORY_CREATED",
		Source:         "github.audit",
		Status:         "succeeded",
		Attempts:       1,
		SourceEventID:  "evt_nats_123",
		OccurredAt:     time.Now().UTC(),
		Payload:        json.RawMessage(`{"repository":{"full_name":"writer/nats"}}`),
	})
	if err != nil {
		t.Fatalf("publish ingestion job lifecycle to NATS: %v", err)
	}
	msg, err := sub.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatalf("receive NATS lifecycle message: %v", err)
	}
	var envelope cerebrov1.EventEnvelope
	if err := proto.Unmarshal(msg.Data, &envelope); err != nil {
		t.Fatalf("decode NATS lifecycle envelope: %v", err)
	}
	if envelope.GetTenantId() != "org_nats_123" || envelope.GetKind() != "aperio.ingestion_job.succeeded" || envelope.GetAttributes()["source_event_id"] != "evt_nats_123" {
		t.Fatalf("unexpected NATS lifecycle envelope: %#v attrs=%#v", &envelope, envelope.GetAttributes())
	}
}
