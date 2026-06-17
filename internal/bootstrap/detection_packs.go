package bootstrap

import (
	"context"

	connect "connectrpc.com/connect"

	aperiov1 "github.com/writer/aperio/gen/aperio/v1"
	"github.com/writer/aperio/internal/ingestionworker"
)

// ListDetectionPacks returns every detection pack the worker knows about,
// each hydrated with the rules it owns. The shape is intentionally flat
// so the operator UI can render the catalog in a single render pass
// without follow-up requests. Provider filter is optional; an empty
// provider returns every pack in display order.
func (a *App) ListDetectionPacks(
	ctx context.Context,
	req *connect.Request[aperiov1.ListDetectionPacksRequest],
) (*connect.Response[aperiov1.ListDetectionPacksResponse], error) {
	if _, err := a.authenticatedOrganization(ctx, req.Header()); err != nil {
		return nil, err
	}
	providerFilter := req.Msg.Provider
	out := &aperiov1.ListDetectionPacksResponse{}
	for _, pack := range ingestionworker.DetectionPacks {
		if providerFilter != "" && providerFilter != pack.Provider {
			continue
		}
		out.Data = append(out.Data, detectionPackProto(pack))
	}
	return connect.NewResponse(out), nil
}

func detectionPackProto(pack ingestionworker.DetectionPack) *aperiov1.DetectionPack {
	rules := ingestionworker.RulesInPack(pack.ID)
	out := &aperiov1.DetectionPack{
		Id:          pack.ID,
		Provider:    pack.Provider,
		Name:        pack.Name,
		Description: pack.Description,
		Version:     pack.Version,
		Rules:       make([]*aperiov1.DetectionPackRule, 0, len(rules)),
	}
	for _, rule := range rules {
		out.Rules = append(out.Rules, &aperiov1.DetectionPackRule{
			Id:              rule.ID,
			Title:           rule.Title,
			Description:     rule.Description,
			Severity:        rule.Severity,
			EventTypes:      append([]string(nil), rule.EventTypes...),
			MitreTechniques: append([]string(nil), rule.MitreTechniques...),
			Intent:          rule.Intent,
			Tags:            append([]string(nil), rule.Tags...),
		})
	}
	return out
}
