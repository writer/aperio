package cerebroclient

import (
	"net/http"
	"strings"

	"github.com/writer/cerebro/sdk/go/cerebroapi"
)

const (
	DefaultRuntimeID = "writer-aperio-saas-dr"
	DefaultSourceID  = "aperio_saas_dr"
	userAgent        = "aperio-cerebro-client"
)

type Config = cerebroapi.Config
type Option = cerebroapi.Option
type HTTPError = cerebroapi.HTTPError

type Client struct {
	*cerebroapi.Client
}

func ConfigFromEnv() Config {
	config := cerebroapi.ConfigFromEnv()
	if strings.TrimSpace(config.RuntimeID) == "" {
		config.RuntimeID = DefaultRuntimeID
	}
	if strings.TrimSpace(config.SourceID) == "" {
		config.SourceID = DefaultSourceID
	}
	if strings.TrimSpace(config.UserAgent) == "" {
		config.UserAgent = userAgent
	}
	if len(config.RuntimeConfig) == 0 {
		config.RuntimeConfig = map[string]string{
			"surface": "aperio_saas_dr",
			"owner":   "aperio",
		}
	}
	return config
}

func WithHTTPClient(httpClient *http.Client) Option {
	return cerebroapi.WithHTTPClient(httpClient)
}

func New(config Config, options ...Option) (*Client, error) {
	if strings.TrimSpace(config.UserAgent) == "" {
		config.UserAgent = userAgent
	}
	client, err := cerebroapi.New(config, options...)
	if err != nil {
		return nil, err
	}
	return &Client{Client: client}, nil
}
