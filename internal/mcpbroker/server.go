package mcpbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/writer/aperio/internal/runtimeutil"
)

const maxFrameBytes = 16 << 20

var contentLengthPattern = regexp.MustCompile(`(?im)(?:^|\r\n)content-length:\s*([0-9]+)\s*(?:\r\n|$)`)

type ToolRunner interface {
	CallTool(ctx context.Context, name string, args any) (any, error)
}

type ResourceReader interface {
	ReadResource(ctx context.Context, params ResourceReadParams) (ResourceContent, error)
}

type ResourceReadParams struct {
	URI       string
	AuthToken string
}

type ResourceContent struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
}

type Server struct {
	Runner         ToolRunner
	Stderr         io.Writer
	ErrorSanitizer func(error) string
}

type rpcRequest struct {
	ID      any
	HasID   bool
	Method  string
	Params  any
	RawBody []byte
}

type toolCallParams struct {
	Name      string
	Arguments any
}

func NewServer(runner ToolRunner) *Server {
	return &Server{
		Runner: runner,
		Stderr: os.Stderr,
	}
}

func EncodeFrame(message any) ([]byte, error) {
	body, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	prefix := []byte(fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)))
	return append(prefix, body...), nil
}

func (s *Server) Run(ctx context.Context, in io.Reader, out io.Writer) error {
	session := &stdioSession{server: s, out: out}
	chunk := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		n, err := in.Read(chunk)
		if n > 0 {
			if processErr := session.feed(ctx, chunk[:n], false); processErr != nil {
				return processErr
			}
		}
		if errors.Is(err, io.EOF) {
			return session.feed(ctx, nil, true)
		}
		if err != nil {
			return err
		}
	}
}

func (s *Server) handleRequest(ctx context.Context, request rpcRequest, out io.Writer) error {
	switch request.Method {
	case "initialize":
		return writeResult(out, request, map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities": map[string]any{
				"tools":     map[string]any{"listChanged": false},
				"resources": map[string]any{"subscribe": false, "listChanged": false},
				"prompts":   map[string]any{"listChanged": false},
			},
			"serverInfo": map[string]any{
				"name":    ServerName,
				"title":   ServerTitle,
				"version": ServerVersion,
			},
		})
	case "notifications/initialized":
		return nil
	case "ping":
		return writeResult(out, request, map[string]any{})
	case "tools/list":
		return writeResult(out, request, map[string]any{"tools": ApprovedTools()})
	case "tools/call":
		return s.handleToolCall(ctx, request, out)
	case "resources/list":
		return writeResult(out, request, map[string]any{"resources": ApprovedResources()})
	case "resources/templates/list":
		return writeResult(out, request, map[string]any{"resourceTemplates": ApprovedResourceTemplates()})
	case "resources/read":
		return s.handleResourceRead(ctx, request, out)
	default:
		return writeError(out, request, -32601, fmt.Sprintf("Method not found: %s", request.Method))
	}
}

func (s *Server) handleToolCall(ctx context.Context, request rpcRequest, out io.Writer) error {
	if !request.HasID {
		return nil
	}
	params, err := parseToolCallParams(request.Params)
	if err != nil {
		return writeResult(out, request, toolErrorResult(s.safeError(err)))
	}
	if s.Runner == nil {
		return writeResult(out, request, toolErrorResult("MCP tool runner is not configured"))
	}
	result, err := s.Runner.CallTool(ctx, params.Name, params.Arguments)
	if err != nil {
		return writeResult(out, request, toolErrorResult(s.safeError(err)))
	}
	text, err := json.Marshal(result)
	if err != nil {
		return writeResult(out, request, toolErrorResult("Tool result could not be encoded"))
	}
	return writeResult(out, request, map[string]any{
		"content": []map[string]string{
			{"type": "text", "text": string(text)},
		},
	})
}

func (s *Server) handleResourceRead(ctx context.Context, request rpcRequest, out io.Writer) error {
	if !request.HasID {
		return nil
	}
	params, err := parseResourceReadParams(request.Params)
	if err != nil {
		return writeError(out, request, -32602, s.safeError(err))
	}
	if s.Runner == nil {
		return writeError(out, request, -32603, "MCP resource reader is not configured")
	}
	reader, ok := s.Runner.(ResourceReader)
	if !ok {
		return writeError(out, request, -32603, "MCP resource reader is not configured")
	}
	content, err := reader.ReadResource(ctx, params)
	if err != nil {
		return writeError(out, request, -32602, s.safeError(err))
	}
	return writeResult(out, request, map[string]any{
		"contents": []ResourceContent{content},
	})
}

func (s *Server) safeError(err error) string {
	if err == nil {
		return "Tool failed"
	}
	if s.ErrorSanitizer != nil {
		if message := s.ErrorSanitizer(err); message != "" {
			return message
		}
	}
	return runtimeutil.RedactError(err, os.Getenv("APERIO_MCP_SHARED_SECRET"))
}

func toolErrorResult(message string) map[string]any {
	if message == "" {
		message = "Tool failed"
	}
	return map[string]any{
		"isError": true,
		"content": []map[string]string{
			{"type": "text", "text": message},
		},
	}
}

func parseToolCallParams(params any) (toolCallParams, error) {
	object, ok := params.(map[string]any)
	if !ok {
		return toolCallParams{}, errors.New("tools/call params must be an object")
	}
	nameValue, ok := object["name"]
	if !ok {
		return toolCallParams{}, errors.New("tools/call name is required")
	}
	name, ok := nameValue.(string)
	if !ok || name == "" {
		return toolCallParams{}, errors.New("tools/call name must be a string")
	}
	args, ok := object["arguments"]
	if !ok {
		args = map[string]any{}
	}
	return toolCallParams{Name: name, Arguments: args}, nil
}

func parseResourceReadParams(params any) (ResourceReadParams, error) {
	object, ok := params.(map[string]any)
	if !ok {
		return ResourceReadParams{}, errors.New("resources/read params must be an object")
	}
	rawURI, ok := object["uri"]
	if !ok {
		return ResourceReadParams{}, errors.New("resources/read uri is required")
	}
	uri, ok := rawURI.(string)
	if !ok || strings.TrimSpace(uri) == "" {
		return ResourceReadParams{}, errors.New("resources/read uri must be a string")
	}
	var authToken string
	if rawToken, ok := object["authToken"]; ok {
		token, ok := rawToken.(string)
		if !ok {
			return ResourceReadParams{}, errors.New("resources/read authToken must be a string")
		}
		authToken = strings.TrimSpace(token)
	}
	return ResourceReadParams{
		URI:       strings.TrimSpace(uri),
		AuthToken: authToken,
	}, nil
}

type stdioSession struct {
	server *Server
	out    io.Writer
	buffer []byte
}

func (s *stdioSession) feed(ctx context.Context, chunk []byte, final bool) error {
	if len(chunk) > 0 {
		s.buffer = append(s.buffer, chunk...)
	}
	for {
		separator := bytes.Index(s.buffer, []byte("\r\n\r\n"))
		if separator == -1 {
			if final && len(bytes.TrimSpace(s.buffer)) > 0 {
				s.buffer = nil
				return writeParseError(s.out, "Parse error")
			}
			return nil
		}
		header := string(s.buffer[:separator])
		match := contentLengthPattern.FindStringSubmatch(header)
		if len(match) != 2 {
			s.buffer = s.buffer[separator+4:]
			if err := writeParseError(s.out, "Missing or invalid Content-Length"); err != nil {
				return err
			}
			continue
		}
		length, err := strconv.Atoi(match[1])
		if err != nil || length < 0 || length > maxFrameBytes {
			s.buffer = s.buffer[separator+4:]
			if err := writeParseError(s.out, "Invalid Content-Length"); err != nil {
				return err
			}
			continue
		}
		bodyStart := separator + 4
		bodyEnd := bodyStart + length
		if len(s.buffer) < bodyEnd {
			if final {
				s.buffer = nil
				return writeParseError(s.out, "Truncated frame")
			}
			return nil
		}
		body := append([]byte(nil), s.buffer[bodyStart:bodyEnd]...)
		s.buffer = s.buffer[bodyEnd:]
		request, err := parseRequest(body)
		if err != nil {
			if err := writeParseError(s.out, "Parse error"); err != nil {
				return err
			}
			continue
		}
		if err := s.server.handleRequest(ctx, request, s.out); err != nil {
			return err
		}
	}
}

func parseRequest(body []byte) (rpcRequest, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return rpcRequest{}, err
	}
	request := rpcRequest{RawBody: body}
	if idRaw, ok := raw["id"]; ok {
		request.HasID = true
		if err := json.Unmarshal(idRaw, &request.ID); err != nil {
			return rpcRequest{}, err
		}
	}
	if methodRaw, ok := raw["method"]; ok {
		_ = json.Unmarshal(methodRaw, &request.Method)
	}
	if paramsRaw, ok := raw["params"]; ok {
		if err := json.Unmarshal(paramsRaw, &request.Params); err != nil {
			return rpcRequest{}, err
		}
	}
	return request, nil
}

func writeResult(out io.Writer, request rpcRequest, result any) error {
	if !request.HasID {
		return nil
	}
	return writeFrame(out, map[string]any{
		"jsonrpc": "2.0",
		"id":      request.ID,
		"result":  result,
	})
}

func writeError(out io.Writer, request rpcRequest, code int, message string) error {
	if !request.HasID {
		return nil
	}
	return writeFrame(out, map[string]any{
		"jsonrpc": "2.0",
		"id":      request.ID,
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}

func writeParseError(out io.Writer, message string) error {
	return writeFrame(out, map[string]any{
		"jsonrpc": "2.0",
		"id":      nil,
		"error": map[string]any{
			"code":    -32700,
			"message": message,
		},
	})
}

func writeFrame(out io.Writer, message any) error {
	frame, err := EncodeFrame(message)
	if err != nil {
		return err
	}
	_, err = out.Write(frame)
	return err
}
