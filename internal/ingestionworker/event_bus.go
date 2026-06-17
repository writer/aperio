package ingestionworker

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	aperiocontractsv1 "github.com/writer/aperio/gen/aperio/contracts/v1"
	cerebrov1 "github.com/writer/cerebro/sdk/go/cerebroapi/genproto/cerebro/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	ingestionEventSourceID              = "aperio"
	ingestionJobSchemaRef               = "aperio/ingestion_job/v1"
	findingLifecycleSchemaRef           = "aperio/finding_lifecycle/v1"
	defaultIngestionNATSURL             = "nats://127.0.0.1:4222"
	defaultIngestionNATSStream          = "CEREBRO_EVENTS"
	ingestionEventPublishConnectTimeout = 5 * time.Second
)

type encodedAperioEvent struct {
	id      string
	subject string
	payload []byte
}

type natsIngestionEventPublisher struct {
	mu         sync.Mutex
	servers    string
	streamName string
	nc         *nats.Conn
	js         nats.JetStreamContext
}

func NewEnvEventPublisher() IngestionEventPublisher {
	if strings.ToLower(strings.TrimSpace(os.Getenv("APERIO_EVENT_BUS"))) != "nats" {
		return noopIngestionEventPublisher{}
	}
	return &natsIngestionEventPublisher{}
}

func (p *natsIngestionEventPublisher) PublishIngestionJobLifecycle(ctx context.Context, event IngestionJobLifecycleEvent) error {
	encoded, err := encodeIngestionJobLifecycleEvent(event)
	if err != nil {
		return err
	}
	return p.publish(ctx, encoded)
}

func (p *natsIngestionEventPublisher) PublishFindingLifecycle(ctx context.Context, event FindingLifecycleEvent) error {
	encoded, err := encodeFindingLifecycleEvent(event)
	if err != nil {
		return err
	}
	return p.publish(ctx, encoded)
}

func (p *natsIngestionEventPublisher) publish(ctx context.Context, event encodedAperioEvent) error {
	servers := strings.TrimSpace(os.Getenv("APERIO_NATS_URL"))
	if servers == "" {
		servers = defaultIngestionNATSURL
	}
	streamName := strings.TrimSpace(os.Getenv("APERIO_NATS_STREAM"))
	if streamName == "" {
		streamName = defaultIngestionNATSStream
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	js, err := p.jetStream(ctx, servers, streamName)
	if err != nil {
		return err
	}
	if _, err := js.StreamInfo(streamName); err != nil {
		_, _ = js.AddStream(&nats.StreamConfig{Name: streamName, Subjects: []string{"events.>"}})
	}
	_, err = js.Publish(event.subject, event.payload, nats.MsgId(event.id), nats.Context(ctx))
	return err
}

func (p *natsIngestionEventPublisher) jetStream(ctx context.Context, servers string, streamName string) (nats.JetStreamContext, error) {
	if p.nc != nil && !p.nc.IsClosed() && p.servers == servers && p.streamName == streamName && p.js != nil {
		return p.js, nil
	}
	if p.nc != nil {
		p.nc.Close()
	}
	nc, err := nats.Connect(servers, nats.Timeout(ingestionEventPublishConnectTimeout))
	if err != nil {
		return nil, err
	}
	js, err := nc.JetStream(nats.Context(ctx))
	if err != nil {
		nc.Close()
		return nil, err
	}
	p.servers = servers
	p.streamName = streamName
	p.nc = nc
	p.js = js
	return js, nil
}

func encodeIngestionJobLifecycleEvent(event IngestionJobLifecycleEvent) (encodedAperioEvent, error) {
	timestamp := timestamppb.New(event.OccurredAt)
	payloadJSON := objectPayloadBytes(event.Payload)
	domainPayload, err := proto.Marshal(&aperiocontractsv1.IngestionJobEvent{
		JobId:          event.JobID,
		OrganizationId: event.OrganizationID,
		IntegrationId:  event.IntegrationID,
		Provider:       event.Provider,
		EventType:      event.EventType,
		Source:         event.Source,
		Actor:          event.Actor,
		OccurredAt:     timestamp,
		Status:         event.Status,
		Attempts:       uint32(event.Attempts),
		SourceEventId:  event.SourceEventID,
		PayloadJson:    payloadJSON,
	})
	if err != nil {
		return encodedAperioEvent{}, err
	}
	kind := ingestionJobEventKind(event.Status)
	return encodeAperioEnvelope(event.OrganizationID, kind, ingestionJobSchemaRef, timestamp, domainPayload, map[string]string{
		"job_id":          event.JobID,
		"integration_id":  event.IntegrationID,
		"provider":        event.Provider,
		"event_type":      event.EventType,
		"source_event_id": event.SourceEventID,
	})
}

func encodeFindingLifecycleEvent(event FindingLifecycleEvent) (encodedAperioEvent, error) {
	timestamp := timestamppb.New(event.OccurredAt)
	domainPayload, err := proto.Marshal(&aperiocontractsv1.FindingLifecycleEvent{
		FindingId:      event.FindingID,
		OrganizationId: event.OrganizationID,
		IntegrationId:  event.IntegrationID,
		PreviousStatus: event.PreviousStatus,
		NextStatus:     event.NextStatus,
		StatusSource:   "system",
		OccurredAt:     timestamp,
		ResolutionNote: event.ResolutionNote,
	})
	if err != nil {
		return encodedAperioEvent{}, err
	}
	kind := findingLifecycleEventKind(event.PreviousStatus, event.NextStatus)
	return encodeAperioEnvelope(event.OrganizationID, kind, findingLifecycleSchemaRef, timestamp, domainPayload, map[string]string{
		"finding_id":      event.FindingID,
		"integration_id":  event.IntegrationID,
		"previous_status": event.PreviousStatus,
		"next_status":     event.NextStatus,
		"status_source":   "system",
	})
}

func encodeAperioEnvelope(tenantID, kind, schemaRef string, occurredAt *timestamppb.Timestamp, domainPayload []byte, attributes map[string]string) (encodedAperioEvent, error) {
	eventID := "evt_" + randomID()
	envelopePayload, err := proto.Marshal(&cerebrov1.EventEnvelope{
		Id:         eventID,
		TenantId:   tenantID,
		SourceId:   ingestionEventSourceID,
		Kind:       kind,
		OccurredAt: occurredAt,
		SchemaRef:  schemaRef,
		Payload:    domainPayload,
		Attributes: compactEventAttributes(attributes),
	})
	if err != nil {
		return encodedAperioEvent{}, err
	}
	return encodedAperioEvent{
		id:      eventID,
		subject: "events." + kind,
		payload: envelopePayload,
	}, nil
}

func ingestionJobEventKind(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "queued":
		return "aperio.ingestion_job.queued"
	case "running":
		return "aperio.ingestion_job.running"
	case "succeeded":
		return "aperio.ingestion_job.succeeded"
	default:
		return "aperio.ingestion_job.failed"
	}
}

func findingLifecycleEventKind(previousStatus string, nextStatus string) string {
	if previousStatus == "RESOLVED" && nextStatus == "OPEN" {
		return "aperio.finding.reopened"
	}
	if nextStatus == "OPEN" {
		return "aperio.finding.opened"
	}
	if nextStatus == "MUTED" {
		return "aperio.finding.muted"
	}
	return "aperio.finding.resolved"
}

func compactEventAttributes(attributes map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range attributes {
		if strings.TrimSpace(value) != "" {
			out[key] = strings.TrimSpace(value)
		}
	}
	return out
}

func objectPayloadBytes(raw json.RawMessage) []byte {
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil || record == nil {
		return []byte(`{}`)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return []byte(`{}`)
	}
	return encoded
}
