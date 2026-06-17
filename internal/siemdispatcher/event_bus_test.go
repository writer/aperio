package siemdispatcher

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	aperiocontractsv1 "github.com/writer/aperio/gen/aperio/contracts/v1"
	cerebrov1 "github.com/writer/aperio/gen/cerebro/v1"
	"github.com/writer/aperio/internal/cerebroclient"
	"google.golang.org/protobuf/proto"
)

func TestEncodeCerebroClaimsFanoutEventUsesStableEnvelope(t *testing.T) {
	occurredAt := time.Date(2026, 6, 5, 20, 0, 0, 0, time.UTC)
	claim := cerebroclient.ClaimToProto(cerebroclient.Claim{
		SubjectURN: "urn:cerebro:org_123:runtime:writer-aperio-sspm:finding:dedupe_123",
		SubjectRef: cerebroEntityRef{
			URN:        "urn:cerebro:org_123:runtime:writer-aperio-sspm:finding:dedupe_123",
			EntityType: "finding",
			Label:      "Public repository",
		},
		Predicate:     "exists",
		ClaimType:     "existence",
		Status:        "asserted",
		SourceEventID: "evt_123",
		ObservedAt:    occurredAt.Format(time.RFC3339Nano),
		Attributes: map[string]string{
			"ruleId":        "github.public_repository_created",
			"sourceEventId": "evt_123",
		},
	})
	encoded, err := encodeCerebroClaimsFanoutEvent(CerebroClaimsFanoutEvent{
		DeliveryID:     "del_123",
		OrganizationID: "org_123",
		DestinationID:  "dst_123",
		RuntimeID:      "writer-aperio-sspm",
		FindingID:      "finding_123",
		DedupeKey:      "dedupe_123",
		OccurredAt:     occurredAt,
		Claims:         []*cerebrov1.Claim{claim},
		Status:         "delivered",
	})
	if err != nil {
		t.Fatalf("encode fanout event: %v", err)
	}
	if encoded.subject != "events.aperio.claim_fanout.delivered" {
		t.Fatalf("subject = %q", encoded.subject)
	}
	var envelope cerebrov1.EventEnvelope
	if err := proto.Unmarshal(encoded.payload, &envelope); err != nil {
		t.Fatalf("decode event envelope: %v", err)
	}
	if envelope.GetTenantId() != "org_123" || envelope.GetSourceId() != "aperio" || envelope.GetKind() != "aperio.claim_fanout.delivered" || envelope.GetSchemaRef() != "aperio/claim_fanout/v1" {
		t.Fatalf("unexpected fanout envelope: %#v", &envelope)
	}
	if envelope.GetAttributes()["delivery_id"] != "del_123" || envelope.GetAttributes()["destination_id"] != "dst_123" || envelope.GetAttributes()["source_runtime_id"] != "writer-aperio-sspm" {
		t.Fatalf("fanout attributes = %#v", envelope.GetAttributes())
	}
	var event aperiocontractsv1.CerebroClaimsFanoutEvent
	if err := proto.Unmarshal(envelope.GetPayload(), &event); err != nil {
		t.Fatalf("decode fanout payload: %v", err)
	}
	if event.GetDeliveryId() != "del_123" || event.GetRuntimeId() != "writer-aperio-sspm" || event.GetStatus() != "delivered" {
		t.Fatalf("unexpected fanout payload: %#v", &event)
	}
	if len(event.GetClaims()) != 1 || event.GetClaims()[0].GetSourceEventId() != "evt_123" || event.GetClaims()[0].GetAttributes()["sourceEventId"] != "evt_123" {
		t.Fatalf("unexpected fanout claims: %#v", event.GetClaims())
	}
}

func TestEnvClaimFanoutPublisherDefaultsToNoop(t *testing.T) {
	t.Setenv("APERIO_EVENT_BUS", "")
	if _, ok := NewEnvClaimFanoutPublisher().(noopClaimFanoutPublisher); !ok {
		t.Fatalf("expected noop publisher when APERIO_EVENT_BUS is unset")
	}
}

func TestNATSCerebroClaimFanoutPublisherPublishesWhenEnabled(t *testing.T) {
	natsURL := strings.TrimSpace(os.Getenv("APERIO_TEST_NATS_URL"))
	if natsURL == "" {
		t.Skip("set APERIO_TEST_NATS_URL to run local NATS Cerebro fanout publisher test")
	}
	nc, err := nats.Connect(natsURL, nats.Timeout(2*time.Second))
	if err != nil {
		t.Fatalf("connect test NATS: %v", err)
	}
	defer nc.Close()
	subject := "events.aperio.claim_fanout.delivered"
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
	publisher := NewEnvClaimFanoutPublisher()
	if _, ok := publisher.(*natsClaimFanoutPublisher); !ok {
		t.Fatalf("expected NATS publisher when APERIO_EVENT_BUS=nats, got %T", publisher)
	}
	err = publisher.PublishCerebroClaimsFanout(context.Background(), CerebroClaimsFanoutEvent{
		DeliveryID:     "del_nats_123",
		OrganizationID: "org_nats_123",
		DestinationID:  "dst_nats_123",
		RuntimeID:      "runtime_nats_123",
		FindingID:      "fnd_nats_123",
		DedupeKey:      "dedupe_nats_123",
		OccurredAt:     time.Now().UTC(),
		Status:         "delivered",
		Claims: []*cerebrov1.Claim{cerebroclient.ClaimToProto(cerebroclient.Claim{
			SubjectURN: "urn:cerebro:org_nats_123:runtime:runtime_nats_123:finding:dedupe_nats_123",
			SubjectRef: cerebroEntityRef{
				URN:        "urn:cerebro:org_nats_123:runtime:runtime_nats_123:finding:dedupe_nats_123",
				EntityType: "finding",
				Label:      "NATS finding",
			},
			Predicate:     "exists",
			ClaimType:     "existence",
			Status:        "asserted",
			SourceEventID: "evt_nats_123",
			ObservedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		})},
	})
	if err != nil {
		t.Fatalf("publish Cerebro claim fanout to NATS: %v", err)
	}
	msg, err := sub.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatalf("receive NATS fanout message: %v", err)
	}
	var envelope cerebrov1.EventEnvelope
	if err := proto.Unmarshal(msg.Data, &envelope); err != nil {
		t.Fatalf("decode NATS fanout envelope: %v", err)
	}
	if envelope.GetTenantId() != "org_nats_123" || envelope.GetKind() != "aperio.claim_fanout.delivered" || envelope.GetAttributes()["source_runtime_id"] != "runtime_nats_123" {
		t.Fatalf("unexpected NATS fanout envelope: %#v attrs=%#v", &envelope, envelope.GetAttributes())
	}
}
