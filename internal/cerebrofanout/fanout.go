package cerebrofanout

import (
	"context"
	"errors"
	"strings"

	"github.com/writer/aperio/internal/cerebroclaims"
	"github.com/writer/aperio/internal/cerebroclient"
)

type ClaimWriter interface {
	WriteClaims(context.Context, cerebroclient.WriteClaimsRequest) (*cerebroclient.WriteClaimsResponse, error)
}

type Service struct {
	writer    ClaimWriter
	tenantID  string
	runtimeID string
}

type FindingPayload struct {
	OrganizationID string
	Kind           string
	OccurredAt     string
	Record         map[string]any
}

type Result struct {
	TenantID               string
	RuntimeID              string
	ClaimCount             int
	ClaimsWritten          uint32
	EntitiesUpserted       uint32
	RelationLinksProjected uint32
	ClaimsRetracted        uint32
	FindingID              string
	DedupeKey              string
	SourceEventID          string
}

func New(config cerebroclient.Config, writer ClaimWriter) (*Service, error) {
	if writer == nil {
		return nil, errors.New("cerebro claim writer is required")
	}
	tenantID := strings.TrimSpace(config.TenantID)
	if tenantID == "" {
		return nil, errors.New("cerebro tenant id is required")
	}
	runtimeID := strings.TrimSpace(config.RuntimeID)
	if runtimeID == "" {
		runtimeID = cerebroclient.DefaultRuntimeID
	}
	return &Service{
		writer:    writer,
		tenantID:  tenantID,
		runtimeID: runtimeID,
	}, nil
}

func (s *Service) FanoutFinding(ctx context.Context, payload FindingPayload) (Result, error) {
	result := Result{
		TenantID:      s.tenantID,
		RuntimeID:     s.runtimeID,
		FindingID:     firstString(payload.Record["findingId"], payload.Record["id"]),
		DedupeKey:     firstString(payload.Record["dedupeKey"]),
		SourceEventID: firstString(payload.Record["sourceEventId"]),
	}
	claims, err := cerebroclaims.Build(cerebroclaims.BuildInput{
		TenantID:       s.tenantID,
		OrganizationID: payload.OrganizationID,
		RuntimeID:      s.runtimeID,
		Payload: cerebroclaims.Payload{
			Kind:       payload.Kind,
			OccurredAt: payload.OccurredAt,
			Record:     payload.Record,
		},
	})
	if err != nil {
		return result, err
	}
	result.ClaimCount = len(claims)
	response, err := s.writer.WriteClaims(ctx, cerebroclient.WriteClaimsRequest{
		RuntimeID: s.runtimeID,
		Claims:    claims,
	})
	if err != nil {
		return result, err
	}
	if response != nil {
		result.ClaimsWritten = response.ClaimsWritten
		result.EntitiesUpserted = response.EntitiesUpserted
		result.RelationLinksProjected = response.RelationLinksProjected
		result.ClaimsRetracted = response.ClaimsRetracted
	}
	return result, nil
}

func firstString(values ...any) string {
	for _, value := range values {
		if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
			return strings.TrimSpace(text)
		}
	}
	return ""
}
