package main

import (
	"context"

	"github.com/writer/aperio/internal/cerebroclient"
)

func ensureCerebroRuntime(ctx context.Context, cfg cerebroclient.Config, options ...cerebroclient.Option) (*cerebroclient.SourceRuntime, bool, error) {
	if !cfg.Enabled() {
		return nil, false, nil
	}
	client, err := cerebroclient.New(cfg, options...)
	if err != nil {
		return nil, true, err
	}
	runtime, err := client.EnsureDefaultRuntime(ctx, cfg)
	if err != nil {
		return nil, true, err
	}
	return runtime, true, nil
}
