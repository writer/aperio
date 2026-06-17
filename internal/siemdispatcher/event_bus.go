package siemdispatcher

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	aperiocontractsv1 "github.com/writer/aperio/gen/aperio/contracts/v1"
	cerebrov1 "github.com/writer/aperio/gen/cerebro/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	siemEventSourceID              = "aperio"
	cerebroClaimFanoutSchemaRef    = "aperio/claim_fanout/v1"
	defaultSIEMNATSURL             = "nats://127.0.0.1:4222"
	defaultSIEMNATSStream          = "CEREBRO_EVENTS"
	siemEventPublishConnectTimeout = 5 * time.Second
)

type CerebroClaimsFanoutEvent struct {
	DeliveryID     string
	OrganizationID string
	DestinationID  string
	RuntimeID      string
	FindingID      string
	DedupeKey      string
	OccurredAt     time.Time
	Claims         []cerebroClaim
	Status         string
	Error          string
}

type ClaimFanoutPublisher interface {
	PublishCerebroClaimsFanout(context.Context, CerebroClaimsFanoutEvent) error
}

type noopClaimFanoutPublisher struct{}

func (noopClaimFanoutPublisher) PublishCerebroClaimsFanout(context.Context, CerebroClaimsFanoutEvent) error {
	return nil
}

type encodedSIEMAperioEvent struct {
	id      string
	subject string
	payload []byte
}

type natsClaimFanoutPublisher struct {
	mu         sync.Mutex
	servers    string
	streamName string
	nc         *nats.Conn
	js         nats.JetStreamContext
}

func NewEnvClaimFanoutPublisher() ClaimFanoutPublisher {
	if strings.ToLower(strings.TrimSpace(os.Getenv("APERIO_EVENT_BUS"))) != "nats" {
		return noopClaimFanoutPublisher{}
	}
	return &natsClaimFanoutPublisher{}
}

func (p *natsClaimFanoutPublisher) PublishCerebroClaimsFanout(ctx context.Context, event CerebroClaimsFanoutEvent) error {
	encoded, err := encodeCerebroClaimsFanoutEvent(event)
	if err != nil {
		return err
	}
	return p.publish(ctx, encoded)
}

func (p *natsClaimFanoutPublisher) publish(ctx context.Context, event encodedSIEMAperioEvent) error {
	servers := strings.TrimSpace(os.Getenv("APERIO_NATS_URL"))
	if servers == "" {
		servers = defaultSIEMNATSURL
	}
	streamName := strings.TrimSpace(os.Getenv("APERIO_NATS_STREAM"))
	if streamName == "" {
		streamName = defaultSIEMNATSStream
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

func (p *natsClaimFanoutPublisher) jetStream(ctx context.Context, servers string, streamName string) (nats.JetStreamContext, error) {
	if p.nc != nil && !p.nc.IsClosed() && p.servers == servers && p.streamName == streamName && p.js != nil {
		return p.js, nil
	}
	if p.nc != nil {
		p.nc.Close()
	}
	nc, err := nats.Connect(servers, nats.Timeout(siemEventPublishConnectTimeout))
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

func (d *Dispatcher) publishCerebroFanout(ctx context.Context, item delivery, dest destination, payload Payload, result sendResult, delivered bool, message string) {
	if len(result.CerebroClaims) == 0 || strings.TrimSpace(result.CerebroRuntimeID) == "" {
		return
	}
	occurredAt, err := time.Parse(time.RFC3339Nano, payload.OccurredAt)
	if err != nil {
		occurredAt = time.Now().UTC()
	}
	status := "failed"
	if delivered {
		status = "delivered"
		message = ""
	}
	_ = d.publisher().PublishCerebroClaimsFanout(ctx, CerebroClaimsFanoutEvent{
		DeliveryID:     item.ID,
		OrganizationID: item.OrganizationID,
		DestinationID:  dest.ID,
		RuntimeID:      result.CerebroRuntimeID,
		FindingID:      result.FindingID,
		DedupeKey:      result.DedupeKey,
		OccurredAt:     occurredAt,
		Claims:         result.CerebroClaims,
		Status:         status,
		Error:          message,
	})
}

func (d *Dispatcher) publisher() ClaimFanoutPublisher {
	if d.claimPublisher != nil {
		return d.claimPublisher
	}
	return noopClaimFanoutPublisher{}
}

func encodeCerebroClaimsFanoutEvent(event CerebroClaimsFanoutEvent) (encodedSIEMAperioEvent, error) {
	occurredAt := timestamppb.New(event.OccurredAt)
	claims := make([]*cerebrov1.Claim, 0, len(event.Claims))
	for _, claim := range event.Claims {
		claims = append(claims, cerebroClaimToProto(claim))
	}
	domainPayload, err := proto.Marshal(&aperiocontractsv1.CerebroClaimsFanoutEvent{
		DeliveryId:     event.DeliveryID,
		OrganizationId: event.OrganizationID,
		DestinationId:  event.DestinationID,
		RuntimeId:      event.RuntimeID,
		FindingId:      event.FindingID,
		DedupeKey:      event.DedupeKey,
		OccurredAt:     occurredAt,
		Claims:         claims,
		Status:         event.Status,
		Error:          event.Error,
	})
	if err != nil {
		return encodedSIEMAperioEvent{}, err
	}
	kind := "aperio.claim_fanout.failed"
	if event.Status == "delivered" {
		kind = "aperio.claim_fanout.delivered"
	}
	return encodeSIEMAperioEnvelope(event.OrganizationID, kind, cerebroClaimFanoutSchemaRef, occurredAt, domainPayload, map[string]string{
		"delivery_id":       event.DeliveryID,
		"destination_id":    event.DestinationID,
		"source_runtime_id": event.RuntimeID,
		"finding_id":        event.FindingID,
		"dedupe_key":        event.DedupeKey,
	})
}

func encodeSIEMAperioEnvelope(tenantID, kind, schemaRef string, occurredAt *timestamppb.Timestamp, domainPayload []byte, attributes map[string]string) (encodedSIEMAperioEvent, error) {
	eventID := "evt_" + randomID()
	payload, err := proto.Marshal(&cerebrov1.EventEnvelope{
		Id:         eventID,
		TenantId:   tenantID,
		SourceId:   siemEventSourceID,
		Kind:       kind,
		OccurredAt: occurredAt,
		SchemaRef:  schemaRef,
		Payload:    domainPayload,
		Attributes: compactEventAttributes(attributes),
	})
	if err != nil {
		return encodedSIEMAperioEvent{}, err
	}
	return encodedSIEMAperioEvent{
		id:      eventID,
		subject: "events." + kind,
		payload: payload,
	}, nil
}

func cerebroClaimToProto(claim cerebroClaim) *cerebrov1.Claim {
	var observedAt *timestamppb.Timestamp
	if observed, err := time.Parse(time.RFC3339Nano, claim.ObservedAt); err == nil {
		observedAt = timestamppb.New(observed)
	}
	return &cerebrov1.Claim{
		Id:            claim.ID,
		SubjectUrn:    claim.SubjectURN,
		SubjectRef:    cerebroEntityRefToProto(claim.SubjectRef),
		Predicate:     claim.Predicate,
		ObjectUrn:     claim.ObjectURN,
		ObjectRef:     optionalCerebroEntityRefToProto(claim.ObjectRef),
		ObjectValue:   claim.ObjectValue,
		ClaimType:     claim.ClaimType,
		Status:        claim.Status,
		SourceEventId: claim.SourceEventID,
		ObservedAt:    observedAt,
		Attributes:    compactEventAttributes(claim.Attributes),
	}
}

func cerebroEntityRefToProto(ref cerebroEntityRef) *cerebrov1.EntityRef {
	return &cerebrov1.EntityRef{
		Urn:        ref.URN,
		EntityType: ref.EntityType,
		Label:      ref.Label,
	}
}

func optionalCerebroEntityRefToProto(ref *cerebroEntityRef) *cerebrov1.EntityRef {
	if ref == nil {
		return nil
	}
	return cerebroEntityRefToProto(*ref)
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
