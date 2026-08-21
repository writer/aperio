package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

func New(baseURL, token string) (*Client, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("APERIO_URL must be an absolute HTTP or HTTPS URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("APERIO_URL must use HTTP or HTTPS")
	}
	return &Client{
		BaseURL: baseURL,
		Token:   strings.TrimSpace(token),
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

func (c *Client) Health(ctx context.Context) (map[string]json.RawMessage, error) {
	result := make(map[string]json.RawMessage, 2)
	for _, path := range []string{"/healthz", "/readyz"} {
		body, err := c.do(ctx, http.MethodGet, path, nil, false)
		if err != nil {
			return nil, err
		}
		result[strings.TrimPrefix(path, "/")] = append(json.RawMessage(nil), body...)
	}
	return result, nil
}

func (c *Client) RPC(ctx context.Context, procedure string, request any) (json.RawMessage, error) {
	procedure = strings.TrimSpace(procedure)
	if procedure == "" || strings.Contains(procedure, "/") {
		return nil, errors.New("invalid RPC procedure")
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	return c.do(ctx, http.MethodPost, "/aperio.v1.AperioService/"+procedure, body, true)
}

func (c *Client) Compat(ctx context.Context, method, path string, request any) (json.RawMessage, error) {
	bodyJSON := ""
	if request != nil {
		body, err := json.Marshal(request)
		if err != nil {
			return nil, err
		}
		bodyJSON = string(body)
	}
	response, err := c.RPC(ctx, "CallApi", map[string]string{
		"method":   strings.ToUpper(strings.TrimSpace(method)),
		"path":     path,
		"bodyJson": bodyJSON,
	})
	if err != nil {
		return nil, err
	}
	var envelope struct {
		BodyJSON string `json:"bodyJson"`
	}
	if err := json.Unmarshal(response, &envelope); err != nil {
		return nil, err
	}
	if !json.Valid([]byte(envelope.BodyJSON)) {
		return nil, errors.New("Aperio compatibility API returned invalid JSON")
	}
	return json.RawMessage(envelope.BodyJSON), nil
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, connectRPC bool) (json.RawMessage, error) {
	request, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	if connectRPC {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Connect-Protocol-Version", "1")
	}
	if c.Token != "" {
		request.Header.Set("Authorization", "Bearer "+c.Token)
	}
	response, err := c.HTTPClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("Aperio returned %s: %s", response.Status, strings.TrimSpace(string(responseBody)))
	}
	if !json.Valid(responseBody) {
		return nil, errors.New("Aperio returned a non-JSON response")
	}
	return responseBody, nil
}
