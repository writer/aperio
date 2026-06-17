package bootstrap

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	aperiov1 "github.com/writer/aperio/gen/aperio/v1"
	"github.com/writer/aperio/gen/aperio/v1/aperiov1connect"
	"github.com/writer/aperio/internal/config"
	"github.com/writer/aperio/internal/googleworkspacepoller"
	"github.com/writer/aperio/internal/telemetry"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const sessionCookieName = "aperio_session"

var processStartedAt = time.Now()
var errInvalidSession = errors.New("invalid session")

// App owns the Go/ConnectRPC HTTP surface. It deliberately keeps only
// infrastructural dependencies here so endpoint implementations stay easy to
// move from the current TypeScript API into Go one route at a time.
type App struct {
	cfg                   config.Config
	db                    *sql.DB
	mux                   *http.ServeMux
	eventBus              *aperioEventBus
	remediationHTTPClient remediationHTTPDoer
	slackAPIBaseURL       string
	cerebroContextClient  saasCerebroContextClient
	cerebroRuntimeID      string
	cerebroMCPServerURL   string
	cerebroOAuthIssuerURL string
}

// dashboardMetrics mirrors the existing web dashboard response shape. Keeping
// this internal shape separate from the generated protobuf type lets the SQL
// aggregation evolve without leaking database-specific details into contracts.
type dashboardMetrics struct {
	TotalRiskScore       int32 `json:"totalRiskScore"`
	OpenCriticalFindings int32 `json:"openCriticalFindings"`
	ConnectedApps        int32 `json:"connectedApps"`
	EventIngestionRate   int32 `json:"eventIngestionRate"`
}

type riskFinding struct {
	RiskScore  int
	Severity   string
	DetectedAt time.Time
	Evidence   map[string]any
	Provider   string
}

type findingRow struct {
	ID               string
	AssetID          string
	Title            string
	Description      string
	Severity         string
	Status           string
	RiskScore        int
	RemediationSteps []string
	Tags             []string
	Evidence         map[string]any
	EvidenceJSON     string
	DetectedAt       time.Time
	ResolvedAt       sql.NullTime
	IntegrationID    string
	Provider         string
	DisplayName      string
	CerebroContext   *aperiov1.FindingCerebroContext
}

type integrationRow struct {
	ID                           string
	Provider                     string
	DisplayName                  string
	ExternalAccountID            string
	Status                       string
	Mode                         string
	Scopes                       []string
	DisabledChecks               []string
	GoogleMailboxScanEnabled     bool
	GoogleMailboxScanClientEmail string
	LastSyncAt                   sql.NullTime
	CreatedAt                    time.Time
}

type siemDestinationRow struct {
	ID             string
	Kind           string
	Name           string
	EndpointURL    string
	FilePath       string
	Index          string
	Streams        []string
	Status         string
	LastDeliveryAt sql.NullTime
	LastError      string
	DeliveriesOk   int32
	DeliveriesFail int32
	CreatedAt      time.Time
}

type shadowItOauthAppRow struct {
	ID                    string
	Provider              string
	Name                  string
	Summary               string
	ExternalID            string
	Labels                []string
	Criticality           string
	ContainsSensitiveData bool
	RiskScore             int32
	LastObservedAt        sql.NullTime
	UserCount             int32
	Scopes                []string
	IntegrationID         string
	IntegrationProvider   string
	IntegrationName       string
}

type shadowItOauthAppGrantRow struct {
	ID              string
	UserEmail       string
	UserExternalID  string
	UserDisplayName string
	Scopes          []string
	Anonymous       bool
	NativeApp       bool
	LastObservedAt  time.Time
}

type securityAssetRow struct {
	ID                    string
	Type                  string
	Provider              string
	Name                  string
	Summary               string
	ExternalID            string
	Labels                []string
	Criticality           string
	ExposureLevel         string
	OwnershipStatus       string
	ContainsSensitiveData bool
	IsPrivileged          bool
	RiskScore             int32
	LastObservedAt        sql.NullTime
	CreatedAt             time.Time
	UpdatedAt             time.Time
	IntegrationID         string
	IntegrationProvider   string
	IntegrationName       string
	OwnerID               string
	OwnerEmail            string
	OwnerDisplayName      string
	BusinessOwnerID       string
	BusinessOwnerEmail    string
	BusinessOwnerName     string
	OpenFindingCount      int32
	ActiveExceptionCount  int32
}

type riskExceptionRow struct {
	ID                   string
	Title                string
	Rationale            string
	CompensatingControls []string
	Status               string
	ExpiresAt            sql.NullTime
	ApprovedAt           sql.NullTime
	CreatedAt            time.Time
	UpdatedAt            time.Time
	AssetID              string
	AssetName            string
	AssetType            string
	FindingID            string
	FindingTitle         string
	FindingSeverity      string
	FindingStatus        string
	CreatedByID          string
	CreatedByEmail       string
	CreatedByName        string
	ApprovedByID         string
	ApprovedByEmail      string
	ApprovedByName       string
}

// NewApp wires routes but does not open network sockets. Tests can mount the
// returned handler directly, while cmd/aperio decides how to listen in runtime.
func NewApp(cfg config.Config, db *sql.DB) *App {
	app := &App{
		cfg:                   cfg,
		db:                    db,
		mux:                   http.NewServeMux(),
		eventBus:              &aperioEventBus{},
		remediationHTTPClient: &http.Client{Timeout: 10 * time.Second},
		slackAPIBaseURL:       "https://slack.com/api",
	}
	app.routes()
	return app
}

// Handler returns the complete HTTP handler stack. CORS is applied outside the
// route mux so every ConnectRPC method and the liveness endpoint share the same
// browser boundary.
func (a *App) Handler() http.Handler {
	return a.withCORS(a.mux)
}

// routes mounts the dependency-free liveness endpoint plus the generated
// ConnectRPC handler. The generated handler provides binary protobuf, JSON,
// gRPC, and gRPC-Web compatibility for the same service implementation.
func (a *App) routes() {
	a.mux.HandleFunc("/healthz", a.handleHealthz)
	a.mux.HandleFunc("/readyz", a.handleReadyz)
	a.mux.HandleFunc(oauthProtectedResourceMetadataPath, a.handleOAuthProtectedResourceMetadata)
	a.mux.HandleFunc(oauthProtectedResourceMetadataMCPPath, a.handleOAuthProtectedResourceMetadata)
	a.mux.HandleFunc(oauthAuthorizationServerMetadataPath, a.handleOAuthAuthorizationServerMetadata)
	a.mux.HandleFunc("/api/v1/integrations/google-workspace/oauth/callback", a.handleGoogleOAuthCallback)
	a.mux.HandleFunc("/api/v1/admin/reports/", a.handleExecutiveReportArtifact)
	a.mux.HandleFunc("/api/v1/compliance/reports/render", a.handleComplianceReport)
	path, handler := aperiov1connect.NewAperioServiceHandler(
		a,
		connect.WithInterceptors(a.wideEventInterceptor()),
	)
	a.mux.Handle(path, handler)
}

// handleHealthz intentionally avoids database access. Orchestrators can use it
// as a cheap process liveness probe without coupling restarts to Postgres state.
func (a *App) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "aperio-go-connect"})
}

func (a *App) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	health := a.healthStatus(r.Context())
	status := http.StatusOK
	if health.Status != "ok" {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, health)
}

// CheckHealth is the first ConnectRPC method exposed by the Go service. It
// matches Cerebro's generated-handler pattern and gives TypeScript clients a
// stable endpoint to verify transport compatibility.
func (a *App) CallApi(
	ctx context.Context,
	req *connect.Request[aperiov1.CallApiRequest],
) (*connect.Response[aperiov1.CallApiResponse], error) {
	if collector, ok := telemetry.CollectorFrom(ctx); ok {
		collector.Dimension("http.tunnel.method", compatMethodLabel(req.Msg.Method))
		collector.Dimension("http.tunnel.route", compatRouteLabel(req.Msg.Path))
	}
	bodyJSON, headers, err := a.handleCompatAPI(ctx, req)
	if err != nil {
		return nil, err
	}
	response := connect.NewResponse(&aperiov1.CallApiResponse{BodyJson: bodyJSON})
	for key, values := range headers {
		for _, value := range values {
			response.Header().Add(key, value)
		}
	}
	return response, nil
}

func (a *App) CheckHealth(
	ctx context.Context,
	_ *connect.Request[aperiov1.CheckHealthRequest],
) (*connect.Response[aperiov1.CheckHealthResponse], error) {
	health := a.healthStatus(ctx)
	components := make([]*aperiov1.HealthComponent, 0, len(health.Components))
	for _, component := range health.Components {
		components = append(components, &aperiov1.HealthComponent{
			Name:   component.Name,
			Status: component.Status,
			Detail: component.Detail,
		})
	}
	return connect.NewResponse(&aperiov1.CheckHealthResponse{
		Status:     health.Status,
		Service:    health.Service,
		CheckedAt:  timestamppb.New(health.CheckedAt),
		Components: components,
	}), nil
}

type healthComponent struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type healthReport struct {
	Status     string            `json:"status"`
	Service    string            `json:"service"`
	CheckedAt  time.Time         `json:"checkedAt"`
	Components []healthComponent `json:"components"`
}

func (a *App) healthStatus(ctx context.Context) healthReport {
	report := healthReport{
		Status:    "ok",
		Service:   "aperio-go-connect",
		CheckedAt: time.Now().UTC(),
		Components: []healthComponent{
			{Name: "process", Status: "ok"},
		},
	}
	database := healthComponent{Name: "database", Status: "ok"}
	if a.db == nil {
		database.Status = "degraded"
		database.Detail = "not_configured"
		report.Status = "degraded"
	} else {
		// Keep readiness probes short-lived so a wedged database does not tie up
		// HTTP workers or make orchestrator health checks cascade.
		pingCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
		if err := a.db.PingContext(pingCtx); err != nil {
			database.Status = "degraded"
			database.Detail = "unhealthy"
			report.Status = "degraded"
		}
	}
	report.Components = append(report.Components, database)
	return report
}

// GetDashboardMetrics is the first product endpoint migrated behind
// ConnectRPC. It preserves the existing tenant cookie model so the web client
// can opt in via NEXT_PUBLIC_CONNECT_API_BASE_URL without changing login flow.
func (a *App) GetDashboardMetrics(
	ctx context.Context,
	req *connect.Request[aperiov1.GetDashboardMetricsRequest],
) (*connect.Response[aperiov1.GetDashboardMetricsResponse], error) {
	organizationID, err := a.authenticatedOrganization(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	metrics, err := a.dashboardMetrics(ctx, organizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("dashboard metrics unavailable"))
	}
	return connect.NewResponse(&aperiov1.GetDashboardMetricsResponse{
		Data: &aperiov1.DashboardMetrics{
			TotalRiskScore:       metrics.TotalRiskScore,
			OpenCriticalFindings: metrics.OpenCriticalFindings,
			ConnectedApps:        metrics.ConnectedApps,
			EventIngestionRate:   metrics.EventIngestionRate,
		},
	}), nil
}

func (a *App) ListFindings(
	ctx context.Context,
	req *connect.Request[aperiov1.ListFindingsRequest],
) (*connect.Response[aperiov1.ListFindingsResponse], error) {
	if collector, ok := telemetry.CollectorFrom(ctx); ok {
		collector.Dimension("http.route.query.severity", req.Msg.Severity)
		collector.Dimension("http.route.query.status", req.Msg.Status)
		collector.Dimension("http.route.query.provider", req.Msg.Provider)
		collector.Dimension("http.route.query.integration_id", req.Msg.IntegrationId)
		collector.Dimension("http.route.query.cursor.present", strconv.FormatBool(req.Msg.Cursor != ""))
		collector.Measurement("http.route.query.limit", int64(normalizedLimit(req.Msg.Limit)))
	}
	organizationID, err := a.authenticatedOrganization(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	if err := validateFindingListRequest(req.Msg); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	// Filtering and pagination stay inside the SQL helper so the telemetry above
	// records request shape while the read path keeps tenant scoping centralized.
	findings, total, err := a.listFindings(ctx, organizationID, req.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("findings unavailable"))
	}
	if collector, ok := telemetry.CollectorFrom(ctx); ok {
		collector.Measurement("result.count", int64(len(findings)))
		collector.Measurement("result.total", int64(total))
	}
	response := &aperiov1.ListFindingsResponse{
		Data: make([]*aperiov1.Finding, 0, len(findings)),
		PageInfo: &aperiov1.PageInfo{
			Total: int32(total),
		},
	}
	limit := normalizedLimit(req.Msg.Limit)
	if len(findings) == limit {
		// The cursor is the final row id from a deterministic detected_at/id sort;
		// the next page rehydrates its timestamp before applying tuple pagination.
		response.PageInfo.NextCursor = findings[len(findings)-1].ID
	}
	for _, finding := range findings {
		response.Data = append(response.Data, finding.toProto())
	}
	return connect.NewResponse(response), nil
}

func (a *App) GetFinding(
	ctx context.Context,
	req *connect.Request[aperiov1.GetFindingRequest],
) (*connect.Response[aperiov1.GetFindingResponse], error) {
	if collector, ok := telemetry.CollectorFrom(ctx); ok {
		collector.Dimension("http.route.param.finding_id.present", strconv.FormatBool(strings.TrimSpace(req.Msg.Id) != ""))
	}
	organizationID, err := a.authenticatedOrganization(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	findingID := strings.TrimSpace(req.Msg.Id)
	if findingID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("finding id is required"))
	}
	finding, err := a.getFinding(ctx, organizationID, findingID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("finding not found"))
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("finding unavailable"))
	}
	enrichCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	a.enrichFindingCerebroContext(enrichCtx, organizationID, &finding)
	return connect.NewResponse(&aperiov1.GetFindingResponse{Data: finding.toProto()}), nil
}

func (a *App) UpdateFindingStatus(
	ctx context.Context,
	req *connect.Request[aperiov1.UpdateFindingStatusRequest],
) (*connect.Response[aperiov1.UpdateFindingStatusResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	body := map[string]any{
		"status":         req.Msg.Status,
		"resolutionNote": req.Msg.ResolutionNote,
	}
	result, err := a.compatUpdateFinding(ctx, strings.TrimSpace(req.Msg.Id), body, auth)
	if err != nil {
		return nil, err
	}
	data, ok := result.(map[string]any)["data"].(map[string]any)
	if !ok {
		return nil, connect.NewError(connect.CodeInternal, errors.New("finding update failed"))
	}
	return connect.NewResponse(&aperiov1.UpdateFindingStatusResponse{
		Data: &aperiov1.FindingStatusUpdate{
			Id:     stringFromAny(data["id"]),
			Status: stringFromAny(data["status"]),
		},
	}), nil
}

func (a *App) RemediateFinding(
	ctx context.Context,
	req *connect.Request[aperiov1.RemediateFindingRequest],
) (*connect.Response[aperiov1.RemediateFindingResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	id := strings.TrimSpace(req.Msg.FindingId)
	body := map[string]any{
		"action":           req.Msg.Action,
		"targetIdentifier": req.Msg.TargetIdentifier,
		"note":             req.Msg.Note,
	}
	if err := a.compatRateLimit(ctx, req.Header(), req.Peer().Addr, http.MethodPost, "/api/v1/findings/"+url.PathEscape(id)+"/remediate", typedRateLimitSubjectBody(auth)); err != nil {
		return nil, err
	}
	result, err := a.compatRemediateFinding(ctx, id, body, auth)
	if err != nil {
		return nil, err
	}
	data, ok := result.(map[string]any)["data"].(map[string]any)
	if !ok {
		return nil, connect.NewError(connect.CodeInternal, errors.New("remediation failed"))
	}
	return connect.NewResponse(&aperiov1.RemediateFindingResponse{
		Data: &aperiov1.RemediationResult{
			FindingId:         stringFromAny(data["findingId"]),
			Action:            stringFromAny(data["action"]),
			Success:           boolFromAny(data["success"]),
			Message:           stringFromAny(data["message"]),
			ProviderRequestId: stringFromAny(data["providerRequestId"]),
			Effects:           stringSlice(data["effects"]),
		},
	}), nil
}

func (a *App) ListConnectorCatalog(
	ctx context.Context,
	req *connect.Request[aperiov1.ListConnectorCatalogRequest],
) (*connect.Response[aperiov1.ListConnectorCatalogResponse], error) {
	if _, err := a.authenticatedOrganization(ctx, req.Header()); err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.ListConnectorCatalogResponse{Data: connectorCatalogProto()}), nil
}

func (a *App) ListIntegrations(
	ctx context.Context,
	req *connect.Request[aperiov1.ListIntegrationsRequest],
) (*connect.Response[aperiov1.ListIntegrationsResponse], error) {
	organizationID, err := a.authenticatedOrganization(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	rows, err := a.listIntegrations(ctx, organizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("integrations unavailable"))
	}
	response := &aperiov1.ListIntegrationsResponse{Data: make([]*aperiov1.IntegrationConnection, 0, len(rows))}
	for _, row := range rows {
		response.Data = append(response.Data, row.toProto())
	}
	return connect.NewResponse(response), nil
}

func (a *App) CreateIntegration(
	ctx context.Context,
	req *connect.Request[aperiov1.CreateIntegrationRequest],
) (*connect.Response[aperiov1.CreateIntegrationResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	result, err := a.compatCreateIntegration(ctx, map[string]any{
		"provider":          req.Msg.Provider,
		"displayName":       req.Msg.DisplayName,
		"externalAccountId": req.Msg.ExternalAccountId,
		"mode":              req.Msg.Mode,
		"credentials": map[string]any{
			"accessToken":   req.Msg.GetCredentials().GetAccessToken(),
			"refreshToken":  req.Msg.GetCredentials().GetRefreshToken(),
			"webhookSecret": req.Msg.GetCredentials().GetWebhookSecret(),
		},
	}, auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.CreateIntegrationResponse{Data: integrationConnectionFromMap(asMap(asMap(result)["data"]))}), nil
}

func (a *App) DeleteIntegration(
	ctx context.Context,
	req *connect.Request[aperiov1.DeleteIntegrationRequest],
) (*connect.Response[aperiov1.DeleteIntegrationResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	if _, err := a.compatDeleteIntegration(ctx, strings.TrimSpace(req.Msg.Id), auth); err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.DeleteIntegrationResponse{Data: &aperiov1.DeleteResult{Ok: true}}), nil
}

func (a *App) GetIntegrationChecks(
	ctx context.Context,
	req *connect.Request[aperiov1.GetIntegrationChecksRequest],
) (*connect.Response[aperiov1.GetIntegrationChecksResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	state, err := a.integrationChecksProto(ctx, strings.TrimSpace(req.Msg.IntegrationId), auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.GetIntegrationChecksResponse{Data: state}), nil
}

func (a *App) UpdateIntegrationChecks(
	ctx context.Context,
	req *connect.Request[aperiov1.UpdateIntegrationChecksRequest],
) (*connect.Response[aperiov1.UpdateIntegrationChecksResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	id := strings.TrimSpace(req.Msg.IntegrationId)
	result, err := a.compatUpdateIntegrationChecks(ctx, id, map[string]any{
		"disabledChecks":   req.Msg.DisabledChecks,
		"disableReason":    req.Msg.DisableReason,
		"disableExpiresAt": req.Msg.DisableExpiresAt,
	}, auth)
	if err != nil {
		return nil, err
	}
	data := asMap(asMap(result)["data"])
	return connect.NewResponse(&aperiov1.UpdateIntegrationChecksResponse{Data: &aperiov1.IntegrationCheckState{
		IntegrationId:  stringFromAny(data["integrationId"]),
		DisabledChecks: stringSlice(data["disabledChecks"]),
		Checks:         findingCheckStatusesProto(findingCheckStatusesFromAny(data["checks"])),
	}}), nil
}

func (a *App) ListConnectorRules(
	ctx context.Context,
	req *connect.Request[aperiov1.ListConnectorRulesRequest],
) (*connect.Response[aperiov1.ListConnectorRulesResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	result, err := a.compatListConnectorRules(ctx, strings.TrimSpace(req.Msg.IntegrationId), auth)
	if err != nil {
		return nil, err
	}
	data := asMap(asMap(result)["data"])
	resp := &aperiov1.ListConnectorRulesResponse{
		IntegrationId: stringFromAny(data["integrationId"]),
		Provider:      stringFromAny(data["provider"]),
	}
	if builtIns, ok := data["builtIn"].([]map[string]any); ok {
		for _, rule := range builtIns {
			resp.BuiltIn = append(resp.BuiltIn, &aperiov1.ConnectorBuiltInRule{
				Id:          stringFromAny(rule["id"]),
				Provider:    stringFromAny(rule["provider"]),
				Title:       stringFromAny(rule["title"]),
				Description: stringFromAny(rule["description"]),
				Severity:    stringFromAny(rule["severity"]),
				EventTypes:  stringSlice(rule["eventTypes"]),
				Enabled:     boolFromAny(rule["enabled"]),
			})
		}
	}
	if customs, ok := data["custom"].([]map[string]any); ok {
		for _, rule := range customs {
			predicateJSON := ""
			if rule["predicate"] != nil {
				if buf, err := json.Marshal(rule["predicate"]); err == nil {
					predicateJSON = string(buf)
				}
			}
			resp.Custom = append(resp.Custom, &aperiov1.ConnectorCustomRule{
				Id:            stringFromAny(rule["id"]),
				Name:          stringFromAny(rule["name"]),
				Severity:      stringFromAny(rule["severity"]),
				EventType:     stringFromAny(rule["eventType"]),
				SubjectField:  stringFromAny(rule["subjectField"]),
				PredicateJson: predicateJSON,
				Enabled:       boolFromAny(rule["enabled"]),
				UpdatedAt:     stringFromAny(rule["updatedAt"]),
			})
		}
	}
	return connect.NewResponse(resp), nil
}

func (a *App) CreateCustomRule(
	ctx context.Context,
	req *connect.Request[aperiov1.CreateCustomRuleRequest],
) (*connect.Response[aperiov1.CreateCustomRuleResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	body, err := customRuleBodyFromProto(req.Msg.Name, req.Msg.Severity, req.Msg.EventType, req.Msg.SubjectField, req.Msg.PredicateJson, req.Msg.Enabled)
	if err != nil {
		return nil, err
	}
	result, err := a.compatCreateCustomRule(ctx, strings.TrimSpace(req.Msg.IntegrationId), body, auth)
	if err != nil {
		return nil, err
	}
	data := asMap(asMap(result)["data"])
	return connect.NewResponse(&aperiov1.CreateCustomRuleResponse{Id: stringFromAny(data["id"])}), nil
}

func (a *App) UpdateCustomRule(
	ctx context.Context,
	req *connect.Request[aperiov1.UpdateCustomRuleRequest],
) (*connect.Response[aperiov1.UpdateCustomRuleResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	body, err := customRuleBodyFromProto(req.Msg.Name, req.Msg.Severity, req.Msg.EventType, req.Msg.SubjectField, req.Msg.PredicateJson, req.Msg.Enabled)
	if err != nil {
		return nil, err
	}
	result, err := a.compatUpdateCustomRule(ctx, strings.TrimSpace(req.Msg.IntegrationId), strings.TrimSpace(req.Msg.RuleId), body, auth)
	if err != nil {
		return nil, err
	}
	data := asMap(asMap(result)["data"])
	return connect.NewResponse(&aperiov1.UpdateCustomRuleResponse{Id: stringFromAny(data["id"])}), nil
}

func (a *App) DeleteCustomRule(
	ctx context.Context,
	req *connect.Request[aperiov1.DeleteCustomRuleRequest],
) (*connect.Response[aperiov1.DeleteCustomRuleResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	result, err := a.compatDeleteCustomRule(ctx, strings.TrimSpace(req.Msg.IntegrationId), strings.TrimSpace(req.Msg.RuleId), auth)
	if err != nil {
		return nil, err
	}
	data := asMap(asMap(result)["data"])
	return connect.NewResponse(&aperiov1.DeleteCustomRuleResponse{Id: stringFromAny(data["id"])}), nil
}

func customRuleBodyFromProto(name, severity, eventType, subjectField, predicateJSON string, enabled bool) (map[string]any, error) {
	body := map[string]any{
		"name":         name,
		"severity":     severity,
		"eventType":    eventType,
		"subjectField": subjectField,
		"enabled":      enabled,
	}
	if strings.TrimSpace(predicateJSON) == "" {
		body["predicate"] = map[string]any{}
	} else {
		var parsed any
		if err := json.Unmarshal([]byte(predicateJSON), &parsed); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("predicate must be a JSON object"))
		}
		body["predicate"] = parsed
	}
	return body, nil
}

func (a *App) GetGoogleMailboxScanConfig(
	ctx context.Context,
	req *connect.Request[aperiov1.GetGoogleMailboxScanConfigRequest],
) (*connect.Response[aperiov1.GetGoogleMailboxScanConfigResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	config, err := a.googleMailboxScanConfigProto(ctx, strings.TrimSpace(req.Msg.IntegrationId), auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.GetGoogleMailboxScanConfigResponse{Data: config}), nil
}

func (a *App) UpdateGoogleMailboxScanConfig(
	ctx context.Context,
	req *connect.Request[aperiov1.UpdateGoogleMailboxScanConfigRequest],
) (*connect.Response[aperiov1.UpdateGoogleMailboxScanConfigResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	result, err := a.compatUpdateGoogleMailboxConfig(ctx, strings.TrimSpace(req.Msg.IntegrationId), map[string]any{
		"enabled":                   req.Msg.Enabled,
		"serviceAccountClientEmail": req.Msg.ServiceAccountClientEmail,
		"privateKey":                req.Msg.PrivateKey,
	}, auth)
	if err != nil {
		return nil, err
	}
	data := asMap(asMap(result)["data"])
	return connect.NewResponse(&aperiov1.UpdateGoogleMailboxScanConfigResponse{Data: googleMailboxScanConfigFromMap(data)}), nil
}

func (a *App) GetGoogleWorkspaceBigQueryConfig(
	ctx context.Context,
	req *connect.Request[aperiov1.GetGoogleWorkspaceBigQueryConfigRequest],
) (*connect.Response[aperiov1.GetGoogleWorkspaceBigQueryConfigResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	config, err := a.googleWorkspaceBigQueryConfigProto(ctx, strings.TrimSpace(req.Msg.IntegrationId), auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.GetGoogleWorkspaceBigQueryConfigResponse{Data: config}), nil
}

func (a *App) UpdateGoogleWorkspaceBigQueryConfig(
	ctx context.Context,
	req *connect.Request[aperiov1.UpdateGoogleWorkspaceBigQueryConfigRequest],
) (*connect.Response[aperiov1.UpdateGoogleWorkspaceBigQueryConfigResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	result, err := a.compatUpdateGoogleWorkspaceBigQueryConfig(ctx, strings.TrimSpace(req.Msg.IntegrationId), map[string]any{
		"enabled":                  req.Msg.Enabled,
		"projectId":                req.Msg.ProjectId,
		"rawDatasetId":             req.Msg.RawDatasetId,
		"datasetId":                req.Msg.DatasetId,
		"location":                 req.Msg.Location,
		"serviceAccountEmail":      req.Msg.ServiceAccountEmail,
		"workloadIdentityProvider": req.Msg.WorkloadIdentityProvider,
		"accessMode":               req.Msg.AccessMode,
	}, auth)
	if err != nil {
		return nil, err
	}
	data := asMap(asMap(result)["data"])
	return connect.NewResponse(&aperiov1.UpdateGoogleWorkspaceBigQueryConfigResponse{Data: googleWorkspaceBigQueryConfigFromMap(data)}), nil
}

func (a *App) ValidateGoogleWorkspaceBigQueryConfig(
	ctx context.Context,
	req *connect.Request[aperiov1.ValidateGoogleWorkspaceBigQueryConfigRequest],
) (*connect.Response[aperiov1.ValidateGoogleWorkspaceBigQueryConfigResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	result, err := googleworkspacepoller.NewBigQueryPoller(a.db).ValidateIntegration(ctx, strings.TrimSpace(req.Msg.IntegrationId), auth.OrganizationID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("integration not found"))
		}
		return nil, internalServerError("validate google workspace bigquery config", err)
	}
	return connect.NewResponse(&aperiov1.ValidateGoogleWorkspaceBigQueryConfigResponse{Data: googleWorkspaceBigQueryValidationProto(result)}), nil
}

func (a *App) StartGoogleWorkspaceOAuth(
	ctx context.Context,
	req *connect.Request[aperiov1.StartGoogleWorkspaceOAuthRequest],
) (*connect.Response[aperiov1.StartGoogleWorkspaceOAuthResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	result, err := a.compatGoogleOAuthStart(ctx, map[string]any{"mode": req.Msg.Mode}, auth)
	if err != nil {
		return nil, err
	}
	data := asMap(asMap(result)["data"])
	return connect.NewResponse(&aperiov1.StartGoogleWorkspaceOAuthResponse{Data: &aperiov1.OAuthStart{Url: stringFromAny(data["url"])}}), nil
}

func (a *App) ForceSyncIntegration(
	ctx context.Context,
	req *connect.Request[aperiov1.ForceSyncIntegrationRequest],
) (*connect.Response[aperiov1.ForceSyncIntegrationResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	id := strings.TrimSpace(req.Msg.IntegrationId)
	if err := a.compatRateLimit(ctx, req.Header(), req.Peer().Addr, http.MethodPost, "/api/v1/integrations/"+url.PathEscape(id)+"/force-sync", typedRateLimitSubjectBody(auth)); err != nil {
		return nil, err
	}
	result, err := a.compatForceSync(ctx, id, auth)
	if err != nil {
		return nil, err
	}
	payload, ok := result.(map[string]any)
	if !ok {
		return nil, connect.NewError(connect.CodeInternal, errors.New("force sync failed"))
	}
	data, _ := payload["data"].(*aperiov1.IntegrationConnection)
	sync := asMap(payload["sync"])
	return connect.NewResponse(&aperiov1.ForceSyncIntegrationResponse{
		Data: data,
		Sync: &aperiov1.SyncSummary{
			SampleCount:    int32(intValue(sync["sampleCount"])),
			EventsIngested: int32(intValue(sync["eventsIngested"])),
			FindingsOpened: int32(intValue(sync["findingsOpened"])),
			Sources:        stringSlice(sync["sources"]),
		},
	}), nil
}

func (a *App) GetIntegrationSyncStatus(
	ctx context.Context,
	req *connect.Request[aperiov1.GetIntegrationSyncStatusRequest],
) (*connect.Response[aperiov1.GetIntegrationSyncStatusResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	status, err := a.getIntegrationSyncStatus(ctx, strings.TrimSpace(req.Msg.IntegrationId), auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.GetIntegrationSyncStatusResponse{Data: status}), nil
}

func (a *App) RunIntegrationSourceSync(
	ctx context.Context,
	req *connect.Request[aperiov1.RunIntegrationSourceSyncRequest],
) (*connect.Response[aperiov1.RunIntegrationSourceSyncResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	id := strings.TrimSpace(req.Msg.IntegrationId)
	if err := a.rateLimitSourceSync(ctx, req.Header(), req.Peer().Addr, id, "source-sync", auth); err != nil {
		return nil, err
	}
	action, err := a.runIntegrationSourceSync(ctx, id, req.Msg.SourceKind, req.Msg.StreamName, auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.RunIntegrationSourceSyncResponse{Data: action}), nil
}

func (a *App) BackfillIntegrationSource(
	ctx context.Context,
	req *connect.Request[aperiov1.BackfillIntegrationSourceRequest],
) (*connect.Response[aperiov1.BackfillIntegrationSourceResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	id := strings.TrimSpace(req.Msg.IntegrationId)
	if err := a.rateLimitSourceSync(ctx, req.Header(), req.Peer().Addr, id, "source-backfill", auth); err != nil {
		return nil, err
	}
	action, err := a.backfillIntegrationSource(ctx, id, req.Msg.SourceKind, req.Msg.StreamName, req.Msg.FromTime, auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.BackfillIntegrationSourceResponse{Data: action}), nil
}

func (a *App) ListSiemCatalog(
	ctx context.Context,
	req *connect.Request[aperiov1.ListSiemCatalogRequest],
) (*connect.Response[aperiov1.ListSiemCatalogResponse], error) {
	if _, err := a.authenticatedOrganization(ctx, req.Header()); err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.ListSiemCatalogResponse{Data: siemCatalogProto()}), nil
}

func (a *App) ListSiemDestinations(
	ctx context.Context,
	req *connect.Request[aperiov1.ListSiemDestinationsRequest],
) (*connect.Response[aperiov1.ListSiemDestinationsResponse], error) {
	organizationID, err := a.authenticatedOrganization(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	rows, err := a.listSiemDestinations(ctx, organizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("siem destinations unavailable"))
	}
	response := &aperiov1.ListSiemDestinationsResponse{Data: make([]*aperiov1.SiemDestination, 0, len(rows))}
	for _, row := range rows {
		response.Data = append(response.Data, row.toProto())
	}
	return connect.NewResponse(response), nil
}

func (a *App) CreateSiemDestination(
	ctx context.Context,
	req *connect.Request[aperiov1.CreateSiemDestinationRequest],
) (*connect.Response[aperiov1.CreateSiemDestinationResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	result, err := a.compatCreateSiem(ctx, map[string]any{
		"kind":        req.Msg.Kind,
		"name":        req.Msg.Name,
		"endpointUrl": req.Msg.EndpointUrl,
		"filePath":    req.Msg.FilePath,
		"index":       req.Msg.Index,
		"streams":     req.Msg.Streams,
		"token":       req.Msg.Token,
	}, auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.CreateSiemDestinationResponse{Data: siemDestinationFromMap(asMap(asMap(result)["data"]))}), nil
}

func (a *App) DeleteSiemDestination(
	ctx context.Context,
	req *connect.Request[aperiov1.DeleteSiemDestinationRequest],
) (*connect.Response[aperiov1.DeleteSiemDestinationResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	if _, err := a.compatDeleteSiem(ctx, strings.TrimSpace(req.Msg.Id), auth); err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.DeleteSiemDestinationResponse{Data: &aperiov1.DeleteResult{Ok: true}}), nil
}

func (a *App) TestSiemDestination(
	ctx context.Context,
	req *connect.Request[aperiov1.TestSiemDestinationRequest],
) (*connect.Response[aperiov1.TestSiemDestinationResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(req.Msg.Id)
	result, err := a.compatTestSiem(ctx, id, auth)
	if err != nil {
		return nil, err
	}
	data := asMap(asMap(result)["data"])
	return connect.NewResponse(&aperiov1.TestSiemDestinationResponse{Data: &aperiov1.SiemTestResult{
		DestinationId: stringFromAny(data["destinationId"]),
		Ok:            boolFromAny(data["ok"]),
		Message:       stringFromAny(data["message"]),
	}}), nil
}

func (a *App) integrationChecksProto(ctx context.Context, id string, auth compatAuth) (*aperiov1.IntegrationCheckState, error) {
	var provider string
	var disabledJSON string
	var metadataJSON string
	if err := a.db.QueryRowContext(ctx, `SELECT provider::text, array_to_json(disabled_checks)::text, disabled_check_metadata::text FROM integration_connections WHERE id = $1 AND organization_id = $2`, id, auth.OrganizationID).Scan(&provider, &disabledJSON, &metadataJSON); err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("integration not found"))
	}
	disabled := []string{}
	_ = json.Unmarshal([]byte(disabledJSON), &disabled)
	disabled, _, _ = applyDisabledCheckExpiry(disabled, decodeDisabledCheckMetadata(metadataJSON), time.Now().UTC())
	return integrationCheckStateProto(id, provider, disabled), nil
}

func integrationCheckStateProto(id string, provider string, disabled []string) *aperiov1.IntegrationCheckState {
	return &aperiov1.IntegrationCheckState{
		IntegrationId:  id,
		DisabledChecks: disabled,
		Checks:         findingCheckStatusesProto(compatFindingCheckStatuses(provider, disabled)),
	}
}

func (a *App) googleMailboxScanConfigProto(ctx context.Context, id string, auth compatAuth) (*aperiov1.GoogleMailboxScanConfig, error) {
	result, err := a.compatGoogleMailboxConfig(ctx, id, auth)
	if err != nil {
		return nil, err
	}
	return googleMailboxScanConfigFromMap(asMap(asMap(result)["data"])), nil
}

func googleMailboxScanConfigFromMap(data map[string]any) *aperiov1.GoogleMailboxScanConfig {
	return &aperiov1.GoogleMailboxScanConfig{
		Enabled:                   boolFromAny(data["enabled"]),
		ServiceAccountClientEmail: optionalStringFromAny(data["serviceAccountClientEmail"]),
	}
}

func (a *App) googleWorkspaceBigQueryConfigProto(ctx context.Context, id string, auth compatAuth) (*aperiov1.GoogleWorkspaceBigQueryConfig, error) {
	result, err := a.compatGoogleWorkspaceBigQueryConfig(ctx, id, auth)
	if err != nil {
		return nil, err
	}
	return googleWorkspaceBigQueryConfigFromMap(asMap(asMap(result)["data"])), nil
}

func googleWorkspaceBigQueryConfigFromMap(data map[string]any) *aperiov1.GoogleWorkspaceBigQueryConfig {
	return &aperiov1.GoogleWorkspaceBigQueryConfig{
		Enabled:                  boolFromAny(data["enabled"]),
		ProjectId:                optionalStringFromAny(data["projectId"]),
		RawDatasetId:             optionalStringFromAny(data["rawDatasetId"]),
		DatasetId:                optionalStringFromAny(data["datasetId"]),
		Location:                 optionalStringFromAny(data["location"]),
		ServiceAccountEmail:      optionalStringFromAny(data["serviceAccountEmail"]),
		WorkloadIdentityProvider: optionalStringFromAny(data["workloadIdentityProvider"]),
		AccessMode:               optionalStringFromAny(data["accessMode"]),
		UpdatedAt:                optionalStringFromAny(data["updatedAt"]),
	}
}

func googleWorkspaceBigQueryValidationProto(result googleworkspacepoller.BigQueryValidationResult) *aperiov1.GoogleWorkspaceBigQueryValidation {
	return &aperiov1.GoogleWorkspaceBigQueryValidation{
		IntegrationId:       result.IntegrationID,
		Ok:                  result.Ok,
		Message:             result.Message,
		ProjectId:           result.ProjectID,
		DatasetId:           result.DatasetID,
		ActivityTable:       result.ActivityTable,
		TableFound:          result.TableFound,
		SampleRows:          int32(result.SampleRows),
		EstimatedBytes:      result.EstimatedBytes,
		RuntimeTokenPresent: result.RuntimeTokenPresent,
	}
}

func connectorCatalogProto() []*aperiov1.ConnectorDefinition {
	catalog := compatConnectorCatalog()
	out := make([]*aperiov1.ConnectorDefinition, 0, len(catalog))
	for _, definition := range catalog {
		out = append(out, connectorDefinitionProto(definition))
	}
	return out
}

func siemCatalogProto() []*aperiov1.SiemDestinationDefinition {
	catalog := compatSiemCatalog()
	out := make([]*aperiov1.SiemDestinationDefinition, 0, len(catalog))
	for _, definition := range catalog {
		out = append(out, siemDestinationDefinitionProto(definition))
	}
	return out
}

func connectorDefinitionProto(definition connectorDefinition) *aperiov1.ConnectorDefinition {
	return &aperiov1.ConnectorDefinition{
		Provider:           definition.Provider,
		Name:               definition.Name,
		Category:           definition.Category,
		Availability:       definition.Availability,
		ReadinessNote:      definition.ReadinessNote,
		Description:        definition.Description,
		ReadScopes:         append([]string{}, definition.ReadScopes...),
		RemediationScopes:  append([]string{}, definition.RemediationScopes...),
		RemediationActions: remediationActionsProto(definition.RemediationActions),
		FindingChecks:      findingChecksProto(definition.FindingChecks),
		DocsUrl:            definition.DocsURL,
		Fields:             connectorFieldsProto(definition.Fields),
	}
}

func connectorFieldsProto(fields []connectorField) []*aperiov1.ConnectorField {
	out := make([]*aperiov1.ConnectorField, 0, len(fields))
	for _, field := range fields {
		out = append(out, &aperiov1.ConnectorField{
			Key:         field.Key,
			Label:       field.Label,
			Placeholder: field.Placeholder,
			Helper:      field.Helper,
			Type:        field.Type,
			Required:    field.Required,
			Secret:      field.Secret,
		})
	}
	return out
}

func remediationActionsProto(actions []remediationAction) []*aperiov1.RemediationAction {
	out := make([]*aperiov1.RemediationAction, 0, len(actions))
	for _, action := range actions {
		out = append(out, &aperiov1.RemediationAction{
			Key:          action.Key,
			Label:        action.Label,
			Description:  action.Description,
			SeverityHint: action.SeverityHint,
		})
	}
	return out
}

func findingChecksProto(checks []findingCheck) []*aperiov1.FindingCheck {
	out := make([]*aperiov1.FindingCheck, 0, len(checks))
	for _, check := range checks {
		out = append(out, &aperiov1.FindingCheck{
			Key:            check.Key,
			Title:          check.Title,
			Description:    check.Description,
			SeverityHint:   check.SeverityHint,
			DefaultEnabled: check.DefaultEnabled,
		})
	}
	return out
}

func findingCheckStatusesProto(statuses []findingCheckStatus) []*aperiov1.FindingCheckStatus {
	out := make([]*aperiov1.FindingCheckStatus, 0, len(statuses))
	for _, status := range statuses {
		out = append(out, &aperiov1.FindingCheckStatus{
			Key:            status.Key,
			Title:          status.Title,
			Description:    status.Description,
			SeverityHint:   status.SeverityHint,
			DefaultEnabled: status.DefaultEnabled,
			Enabled:        status.Enabled,
		})
	}
	return out
}

func findingCheckStatusesFromAny(value any) []findingCheckStatus {
	switch typed := value.(type) {
	case []findingCheckStatus:
		return typed
	case []any:
		statuses := make([]findingCheckStatus, 0, len(typed))
		for _, item := range typed {
			data := asMap(item)
			statuses = append(statuses, findingCheckStatus{
				findingCheck: findingCheck{
					Key:            stringFromAny(data["key"]),
					Title:          stringFromAny(data["title"]),
					Description:    stringFromAny(data["description"]),
					SeverityHint:   stringFromAny(data["severityHint"]),
					DefaultEnabled: boolFromAny(data["defaultEnabled"]),
				},
				Enabled: boolFromAny(data["enabled"]),
			})
		}
		return statuses
	}
	return []findingCheckStatus{}
}

func integrationConnectionFromMap(data map[string]any) *aperiov1.IntegrationConnection {
	return &aperiov1.IntegrationConnection{
		Id:                           stringFromAny(data["id"]),
		Provider:                     stringFromAny(data["provider"]),
		DisplayName:                  stringFromAny(data["displayName"]),
		ExternalAccountId:            stringFromAny(data["externalAccountId"]),
		Status:                       stringFromAny(data["status"]),
		Mode:                         stringFromAny(data["mode"]),
		Scopes:                       stringSlice(data["scopes"]),
		DisabledChecks:               stringSlice(data["disabledChecks"]),
		GoogleMailboxScanEnabled:     boolFromAny(data["googleMailboxScanEnabled"]),
		GoogleMailboxScanClientEmail: optionalStringFromAny(data["googleMailboxScanClientEmail"]),
		LastSyncAt:                   optionalStringFromAny(data["lastSyncAt"]),
		CreatedAt:                    stringFromAny(data["createdAt"]),
	}
}

func siemDestinationFromMap(data map[string]any) *aperiov1.SiemDestination {
	return &aperiov1.SiemDestination{
		Id:             stringFromAny(data["id"]),
		Kind:           stringFromAny(data["kind"]),
		Name:           stringFromAny(data["name"]),
		EndpointUrl:    optionalStringFromAny(data["endpointUrl"]),
		FilePath:       optionalStringFromAny(data["filePath"]),
		Index:          optionalStringFromAny(data["index"]),
		Streams:        stringSlice(data["streams"]),
		Status:         stringFromAny(data["status"]),
		LastDeliveryAt: optionalStringFromAny(data["lastDeliveryAt"]),
		LastError:      optionalStringFromAny(data["lastError"]),
		DeliveriesOk:   int32(intValue(data["deliveriesOk"])),
		DeliveriesFail: int32(intValue(data["deliveriesFail"])),
		CreatedAt:      stringFromAny(data["createdAt"]),
	}
}

func siemDestinationDefinitionProto(definition siemDestinationDefinition) *aperiov1.SiemDestinationDefinition {
	return &aperiov1.SiemDestinationDefinition{
		Kind:           definition.Kind,
		Name:           definition.Name,
		Vendor:         definition.Vendor,
		Description:    definition.Description,
		Category:       definition.Category,
		DocsUrl:        definition.DocsURL,
		DefaultStreams: append([]string{}, definition.DefaultStreams...),
		Fields:         siemFieldsProto(definition.Fields),
	}
}

func siemFieldsProto(fields []siemField) []*aperiov1.SiemField {
	out := make([]*aperiov1.SiemField, 0, len(fields))
	for _, field := range fields {
		out = append(out, &aperiov1.SiemField{
			Key:         field.Key,
			Label:       field.Label,
			Placeholder: field.Placeholder,
			Helper:      field.Helper,
			Type:        field.Type,
			Required:    field.Required,
			Secret:      field.Secret,
		})
	}
	return out
}

func stringFromAny(value any) string {
	text, _ := value.(string)
	return text
}

func optionalStringFromAny(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case *string:
		if typed != nil {
			return *typed
		}
	}
	return ""
}

func boolFromAny(value any) bool {
	typed, _ := value.(bool)
	return typed
}

func optionalBoolFromAny(value any) *bool {
	switch typed := value.(type) {
	case bool:
		result := typed
		return &result
	case *bool:
		return typed
	}
	return nil
}

func typedRateLimitSubjectBody(auth compatAuth) map[string]any {
	return map[string]any{"email": auth.Email}
}

func (a *App) ListShadowItOauthApps(
	ctx context.Context,
	req *connect.Request[aperiov1.ListShadowItOauthAppsRequest],
) (*connect.Response[aperiov1.ListShadowItOauthAppsResponse], error) {
	organizationID, err := a.authenticatedOrganization(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	rows, err := a.listShadowItOauthApps(ctx, organizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("shadow it oauth apps unavailable"))
	}
	response := &aperiov1.ListShadowItOauthAppsResponse{Data: make([]*aperiov1.ShadowItOauthApp, 0, len(rows))}
	for _, row := range rows {
		response.Data = append(response.Data, row.toProto())
	}
	return connect.NewResponse(response), nil
}

func (a *App) ListShadowItOauthAppGrants(
	ctx context.Context,
	req *connect.Request[aperiov1.ListShadowItOauthAppGrantsRequest],
) (*connect.Response[aperiov1.ListShadowItOauthAppGrantsResponse], error) {
	organizationID, err := a.authenticatedOrganization(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	assetID := strings.TrimSpace(req.Msg.AssetId)
	if assetID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("asset id is required"))
	}
	app, grants, err := a.listShadowItOauthAppGrants(ctx, organizationID, assetID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("oauth app not found"))
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("oauth app grants unavailable"))
	}
	response := &aperiov1.ListShadowItOauthAppGrantsResponse{
		Data: &aperiov1.ShadowItOauthAppDetail{
			App:    app,
			Grants: make([]*aperiov1.ShadowItOauthAppGrant, 0, len(grants)),
		},
	}
	for _, grant := range grants {
		response.Data.Grants = append(response.Data.Grants, grant.toProto())
	}
	return connect.NewResponse(response), nil
}

func (a *App) ListSecurityAssets(
	ctx context.Context,
	req *connect.Request[aperiov1.ListSecurityAssetsRequest],
) (*connect.Response[aperiov1.ListSecurityAssetsResponse], error) {
	organizationID, err := a.authenticatedOrganization(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	rows, err := a.listSecurityAssets(ctx, organizationID, req.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("security assets unavailable"))
	}
	response := &aperiov1.ListSecurityAssetsResponse{Data: make([]*aperiov1.SecurityAsset, 0, len(rows))}
	for _, row := range rows {
		response.Data = append(response.Data, row.toProto())
	}
	return connect.NewResponse(response), nil
}

func (a *App) ListRiskExceptions(
	ctx context.Context,
	req *connect.Request[aperiov1.ListRiskExceptionsRequest],
) (*connect.Response[aperiov1.ListRiskExceptionsResponse], error) {
	organizationID, err := a.authenticatedOrganization(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	rows, err := a.listRiskExceptions(ctx, organizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("risk exceptions unavailable"))
	}
	response := &aperiov1.ListRiskExceptionsResponse{Data: make([]*aperiov1.RiskException, 0, len(rows))}
	for _, row := range rows {
		response.Data = append(response.Data, row.toProto())
	}
	return connect.NewResponse(response), nil
}

func (a *App) ListEmailDomainHealth(
	ctx context.Context,
	req *connect.Request[aperiov1.ListEmailDomainHealthRequest],
) (*connect.Response[aperiov1.ListEmailDomainHealthResponse], error) {
	return a.listEmailDomainHealth(ctx, req)
}

func (a *App) GetEmailDomainHealth(
	ctx context.Context,
	req *connect.Request[aperiov1.GetEmailDomainHealthRequest],
) (*connect.Response[aperiov1.GetEmailDomainHealthResponse], error) {
	return a.getEmailDomainHealth(ctx, req)
}

func (a *App) RefreshEmailDomainHealth(
	ctx context.Context,
	req *connect.Request[aperiov1.RefreshEmailDomainHealthRequest],
) (*connect.Response[aperiov1.RefreshEmailDomainHealthResponse], error) {
	return a.refreshEmailDomainHealth(ctx, req)
}

func (a *App) authenticatedOrganization(ctx context.Context, header http.Header) (string, error) {
	if a.db == nil {
		return "", connect.NewError(connect.CodeUnavailable, errors.New("database not configured"))
	}
	organizationID, err := a.organizationIDFromSession(ctx, header)
	if err != nil {
		if errors.Is(err, errInvalidSession) || errors.Is(err, sql.ErrNoRows) {
			return "", connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
		}
		return "", connect.NewError(connect.CodeUnavailable, errors.New("authentication store unavailable"))
	}
	if collector, ok := telemetry.CollectorFrom(ctx); ok {
		collector.SetOrganization(organizationID)
	}
	return organizationID, nil
}

type rpcWideEvent struct {
	Method         string
	OrganizationID string
	Status         string
	Started        time.Time
	Dimensions     map[string]string
	Measurements   map[string]int64
}

// wideEventInterceptor emits exactly one canonical wide event per unary RPC.
// Centralizing emission here guarantees every method (current and future) is
// instrumented consistently; handlers enrich the same event through the
// telemetry.Collector seeded into the request context.
func (a *App) wideEventInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			started := time.Now()
			ctx, collector := telemetry.NewCollector(ctx)
			res, err := next(ctx, req)
			status := "success"
			if err != nil {
				status = connect.CodeOf(err).String()
			}
			organizationID, dimensions, measurements := collector.Snapshot()
			a.emitRPCWideEvent(rpcWideEvent{
				Method:         procedureMethod(req.Spec().Procedure),
				OrganizationID: organizationID,
				Status:         status,
				Started:        started,
				Dimensions:     dimensions,
				Measurements:   measurements,
			})
			return res, err
		}
	}
}

// procedureMethod extracts the bare RPC method from a fully-qualified Connect
// procedure such as "/aperio.v1.AperioService/ListFindings".
func procedureMethod(procedure string) string {
	if index := strings.LastIndex(procedure, "/"); index >= 0 {
		return procedure[index+1:]
	}
	return procedure
}

func (a *App) emitRPCWideEvent(event rpcWideEvent) {
	telemetry.EmitWide(a.buildRPCWideEvent(event))
}

func (a *App) buildRPCWideEvent(event rpcWideEvent) telemetry.WideEvent {
	mergedDimensions := map[string]string{
		"main":                "true",
		"unit_of_work":        "connect_rpc",
		"service.name":        "aperio-go-connect",
		"service.environment": envOrDefault("APERIO_ENVIRONMENT", "development"),
		"service.version":     envOrDefault("APERIO_VERSION", "unknown"),
		"service.build.git_hash": envOrDefault(
			"APERIO_GIT_SHA",
			envOrDefault("GITHUB_SHA", "unknown"),
		),
		"instance.id":         hostnameOrUnknown(),
		"go.version":          runtime.Version(),
		"rpc.system":          "connect",
		"rpc.service":         "aperio.v1.AperioService",
		"rpc.method":          event.Method,
		"http.route":          "/aperio.v1.AperioService/" + event.Method,
		"http.request.method": "POST",
		"user.org.id":         event.OrganizationID,
		"status":              event.Status,
	}
	if event.Status != "success" {
		mergedDimensions["error.kind"] = event.Status
	}
	for key, value := range event.Dimensions {
		if strings.TrimSpace(value) != "" {
			mergedDimensions[key] = value
		}
	}
	mergedMeasurements := map[string]int64{
		"duration_ms":        time.Since(event.Started).Milliseconds(),
		"process.uptime_ms":  time.Since(processStartedAt).Milliseconds(),
		"instance.cpu_count": int64(runtime.NumCPU()),
		"process.pid":        int64(os.Getpid()),
	}
	for key, value := range event.Measurements {
		mergedMeasurements[key] = value
	}
	return telemetry.WideEvent{
		Name:         "aperio.connect_rpc",
		Organization: event.OrganizationID,
		Service:      "aperio-go-connect",
		Dimensions:   mergedDimensions,
		Measurements: mergedMeasurements,
	}
}

func envOrDefault(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func hostnameOrUnknown() string {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		return "unknown"
	}
	return hostname
}

// organizationIDFromSession validates Aperio's HttpOnly cookie session against
// the same user_sessions table used by the TypeScript API. It accepts only live,
// unrevoked sessions for active users, respects MFA completion, and enforces the
// same idle-timeout control before returning the tenant boundary.
func (a *App) organizationIDFromSession(ctx context.Context, header http.Header) (string, error) {
	token := sessionToken(header)
	if token == "" {
		return "", errInvalidSession
	}
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", errInvalidSession
	}
	tokenHash := hashOpaqueToken(parts[1])

	var organizationID, sessionID string
	var lastSeenAt time.Time
	err := a.db.QueryRowContext(ctx, `
		SELECT us.id, u.organization_id, us.last_seen_at
		FROM user_sessions us
		JOIN users u ON u.id = us.user_id AND u.organization_id = us.organization_id
		WHERE us.id = $1
		  AND us.token_hash = $2
		  AND us.revoked_at IS NULL
		  AND us.expires_at > NOW()
		  AND u.is_active = TRUE
		  AND (u.mfa_enabled = FALSE OR us.mfa_verified_at IS NOT NULL)
	`, parts[0], tokenHash).Scan(&sessionID, &organizationID, &lastSeenAt)
	if err != nil {
		return "", err
	}
	if time.Since(lastSeenAt) > time.Duration(a.cfg.SessionIdleMinutes)*time.Minute {
		_, _ = a.db.ExecContext(ctx, `UPDATE user_sessions SET revoked_at = NOW() WHERE id = $1`, sessionID)
		return "", errInvalidSession
	}
	if time.Since(lastSeenAt) > time.Minute {
		_, _ = a.db.ExecContext(ctx, `UPDATE user_sessions SET last_seen_at = NOW() WHERE id = $1`, sessionID)
	}
	return organizationID, nil
}

func sessionToken(header http.Header) string {
	if authorization := strings.TrimSpace(header.Get("Authorization")); authorization != "" {
		scheme, value, ok := strings.Cut(authorization, " ")
		if ok && strings.EqualFold(scheme, "Bearer") && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return sessionCookie(header.Get("Cookie"))
}

// sessionCookie extracts the opaque session token from the Cookie header without
// depending on Express-style middleware. Keeping this small and explicit makes
// the cross-runtime auth boundary auditable.
func sessionCookie(header string) string {
	for _, entry := range strings.Split(header, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(entry), "=")
		if ok && name == sessionCookieName {
			decoded, err := url.QueryUnescape(value)
			if err != nil {
				return value
			}
			return decoded
		}
	}
	return ""
}

// dashboardMetrics performs the read-side aggregation for the dashboard. The
// query is intentionally tenant-scoped and read-only so it is a safe first slice
// to serve from the Go runtime before moving mutation-heavy endpoints.
func (a *App) dashboardMetrics(ctx context.Context, organizationID string) (dashboardMetrics, error) {
	var metrics dashboardMetrics
	oneMinuteAgo := time.Now().Add(-1 * time.Minute)
	findings, err := a.openFindings(ctx, organizationID)
	if err != nil {
		return metrics, err
	}
	metrics.TotalRiskScore = int32(aggregateRiskScore(findings))
	row := a.db.QueryRowContext(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE sf.status = 'OPEN' AND sf.severity = 'CRITICAL')::int,
			(SELECT COUNT(*)::int FROM integration_connections ic WHERE ic.organization_id = $1 AND ic.status = 'CONNECTED'),
			(SELECT COUNT(*)::int FROM ingested_events ie WHERE ie.organization_id = $1 AND ie.created_at >= $2)
		FROM security_findings sf
		WHERE sf.organization_id = $1
	`, organizationID, oneMinuteAgo)
	err = row.Scan(
		&metrics.OpenCriticalFindings,
		&metrics.ConnectedApps,
		&metrics.EventIngestionRate,
	)
	return metrics, err
}

func (a *App) listFindings(
	ctx context.Context,
	organizationID string,
	req *aperiov1.ListFindingsRequest,
) ([]findingRow, int, error) {
	where, args := findingFilterWhere(organizationID, req)
	// Count and list use the same WHERE fragments so the UI total matches the
	// paginated rows exactly, including provider and integration filters.
	countQuery := `SELECT COUNT(*)::int FROM security_findings sf JOIN integration_connections ic ON ic.id = sf.integration_id WHERE ` + strings.Join(where, " AND ")
	var total int
	if err := a.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	listWhere := append([]string{}, where...)
	listArgs := append([]any{}, args...)
	if cursor := strings.TrimSpace(req.Cursor); cursor != "" {
		var cursorDetectedAt time.Time
		// Cursor ids are tenant-scoped before their timestamp is used, preventing a
		// user from probing another organization's finding ids through pagination.
		err := a.db.QueryRowContext(ctx, `
			SELECT detected_at
			FROM security_findings
			WHERE organization_id = $1 AND id = $2
		`, organizationID, cursor).Scan(&cursorDetectedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return []findingRow{}, total, nil
		}
		if err != nil {
			return nil, 0, err
		}
		listArgs = append(listArgs, cursorDetectedAt, cursor)
		listWhere = append(listWhere, "(sf.detected_at, sf.id) < ($"+intPlaceholder(len(listArgs)-1)+", $"+intPlaceholder(len(listArgs))+")")
	}

	listArgs = append(listArgs, normalizedLimit(req.Limit))
	query := `
		SELECT
			sf.id,
			COALESCE(sf.asset_id, ''),
			sf.title,
			sf.description,
			sf.severity::text,
			sf.status::text,
			sf.risk_score,
			COALESCE(to_json(sf.remediation_steps)::text, '[]'),
			COALESCE(to_json(sf.tags)::text, '[]'),
			sf.evidence::text,
			sf.detected_at,
			sf.resolved_at,
			ic.id,
			ic.provider::text,
			ic.display_name
		FROM security_findings sf
		JOIN integration_connections ic ON ic.id = sf.integration_id
		WHERE ` + strings.Join(listWhere, " AND ") + `
		ORDER BY sf.detected_at DESC, sf.id DESC
		LIMIT $` + intPlaceholder(len(listArgs))
	rows, err := a.db.QueryContext(ctx, query, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	findings, err := scanFindingRows(rows)
	return findings, total, err
}

func (a *App) getFinding(ctx context.Context, organizationID string, findingID string) (findingRow, error) {
	row := a.db.QueryRowContext(ctx, `
		SELECT
			sf.id,
			COALESCE(sf.asset_id, ''),
			sf.title,
			sf.description,
			sf.severity::text,
			sf.status::text,
			sf.risk_score,
			COALESCE(to_json(sf.remediation_steps)::text, '[]'),
			COALESCE(to_json(sf.tags)::text, '[]'),
			sf.evidence::text,
			sf.detected_at,
			sf.resolved_at,
			ic.id,
			ic.provider::text,
			ic.display_name
		FROM security_findings sf
		JOIN integration_connections ic ON ic.id = sf.integration_id
		WHERE sf.organization_id = $1 AND sf.id = $2
	`, organizationID, findingID)
	return scanFindingRow(row)
}

func findingFilterWhere(organizationID string, req *aperiov1.ListFindingsRequest) ([]string, []any) {
	where := []string{"sf.organization_id = $1"}
	args := []any{organizationID}
	appendFilter := func(condition string, value string) {
		args = append(args, value)
		where = append(where, condition+" $"+intPlaceholder(len(args)))
	}
	if status := strings.TrimSpace(req.Status); status != "" && status != "ALL" {
		appendFilter("sf.status::text =", status)
	}
	if severity := strings.TrimSpace(req.Severity); severity != "" {
		appendFilter("sf.severity::text =", severity)
	}
	if provider := strings.TrimSpace(req.Provider); provider != "" {
		appendFilter("ic.provider::text =", provider)
	}
	if integrationID := strings.TrimSpace(req.IntegrationId); integrationID != "" {
		appendFilter("sf.integration_id =", integrationID)
	}
	return where, args
}

type findingScanner interface {
	Scan(dest ...any) error
}

func scanFindingRows(rows *sql.Rows) ([]findingRow, error) {
	var findings []findingRow
	for rows.Next() {
		finding, err := scanFindingRow(rows)
		if err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

func scanFindingRow(scanner findingScanner) (findingRow, error) {
	var finding findingRow
	var remediationJSON string
	var tagsJSON string
	if err := scanner.Scan(
		&finding.ID,
		&finding.AssetID,
		&finding.Title,
		&finding.Description,
		&finding.Severity,
		&finding.Status,
		&finding.RiskScore,
		&remediationJSON,
		&tagsJSON,
		&finding.EvidenceJSON,
		&finding.DetectedAt,
		&finding.ResolvedAt,
		&finding.IntegrationID,
		&finding.Provider,
		&finding.DisplayName,
	); err != nil {
		return finding, err
	}
	_ = json.Unmarshal([]byte(remediationJSON), &finding.RemediationSteps)
	_ = json.Unmarshal([]byte(tagsJSON), &finding.Tags)
	// JSON parse failures are tolerated here because malformed evidence should
	// not break list rendering; the raw evidence JSON remains available for detail
	// views and future repair tooling.
	_ = json.Unmarshal([]byte(finding.EvidenceJSON), &finding.Evidence)
	return finding, nil
}

func (finding findingRow) toProto() *aperiov1.Finding {
	riskScore := calculateFindingRiskScore(riskFinding{
		RiskScore:  finding.RiskScore,
		Severity:   finding.Severity,
		DetectedAt: finding.DetectedAt,
		Evidence:   finding.Evidence,
		Provider:   finding.Provider,
	})
	resolvedAt := ""
	if finding.ResolvedAt.Valid {
		resolvedAt = finding.ResolvedAt.Time.UTC().Format(time.RFC3339Nano)
	}
	return &aperiov1.Finding{
		Id:               finding.ID,
		AssetId:          finding.AssetID,
		Title:            finding.Title,
		Description:      finding.Description,
		Severity:         finding.Severity,
		Status:           finding.Status,
		RiskScore:        int32(riskScore),
		RemediationSteps: finding.RemediationSteps,
		EvidenceJson:     finding.EvidenceJSON,
		DetectedAt:       finding.DetectedAt.UTC().Format(time.RFC3339Nano),
		ResolvedAt:       resolvedAt,
		Tags:             finding.Tags,
		Integration: &aperiov1.FindingIntegration{
			Id:          finding.IntegrationID,
			Provider:    finding.Provider,
			DisplayName: finding.DisplayName,
		},
		CerebroContext: finding.CerebroContext,
	}
}

func validateFindingFilters(severity string, status string, provider string) error {
	if severity != "" && !allowedValue(severity, "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") {
		return errors.New("invalid severity filter")
	}
	if status != "" && !allowedValue(status, "OPEN", "RESOLVED", "MUTED", "ALL") {
		return errors.New("invalid status filter")
	}
	if provider != "" && !allowedValue(provider, "GITHUB", "SLACK", "GOOGLE_WORKSPACE", "ONE_PASSWORD", "OKTA", "MICROSOFT_365", "ATLASSIAN", "SALESFORCE") {
		return errors.New("invalid provider filter")
	}
	return nil
}

func allowedValue(value string, allowed ...string) bool {
	for _, entry := range allowed {
		if value == entry {
			return true
		}
	}
	return false
}

func normalizedLimit(limit int32) int {
	if limit <= 0 {
		return 50
	}
	return int(limit)
}

func validateFindingListRequest(req *aperiov1.ListFindingsRequest) error {
	if req.Limit > 100 {
		return errors.New("limit must be less than or equal to 100")
	}
	return validateFindingFilters(req.Severity, req.Status, req.Provider)
}

func intPlaceholder(value int) string {
	return strconv.Itoa(value)
}

func (a *App) listIntegrations(ctx context.Context, organizationID string) ([]integrationRow, error) {
	rows, err := a.db.QueryContext(ctx, `
		SELECT
			id,
			provider::text,
			display_name,
			external_account_id,
			status::text,
			mode::text,
			array_to_json(scopes)::text,
			array_to_json(disabled_checks)::text,
			disabled_check_metadata::text,
			google_mailbox_scan_client_email IS NOT NULL AND encrypted_google_mailbox_scan_private_key IS NOT NULL,
			COALESCE(google_mailbox_scan_client_email, ''),
			last_sync_at,
			created_at
		FROM integration_connections
		WHERE organization_id = $1
		ORDER BY created_at DESC
	`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var integrations []integrationRow
	for rows.Next() {
		var row integrationRow
		var scopesJSON, disabledChecksJSON, disabledChecksMetadataJSON string
		if err := rows.Scan(
			&row.ID,
			&row.Provider,
			&row.DisplayName,
			&row.ExternalAccountID,
			&row.Status,
			&row.Mode,
			&scopesJSON,
			&disabledChecksJSON,
			&disabledChecksMetadataJSON,
			&row.GoogleMailboxScanEnabled,
			&row.GoogleMailboxScanClientEmail,
			&row.LastSyncAt,
			&row.CreatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(scopesJSON), &row.Scopes)
		_ = json.Unmarshal([]byte(disabledChecksJSON), &row.DisabledChecks)
		row.DisabledChecks, _, _ = applyDisabledCheckExpiry(row.DisabledChecks, decodeDisabledCheckMetadata(disabledChecksMetadataJSON), time.Now().UTC())
		integrations = append(integrations, row)
	}
	return integrations, rows.Err()
}

func (row integrationRow) toProto() *aperiov1.IntegrationConnection {
	return &aperiov1.IntegrationConnection{
		Id:                           row.ID,
		Provider:                     row.Provider,
		DisplayName:                  row.DisplayName,
		ExternalAccountId:            row.ExternalAccountID,
		Status:                       row.Status,
		Mode:                         row.Mode,
		Scopes:                       row.Scopes,
		DisabledChecks:               row.DisabledChecks,
		GoogleMailboxScanEnabled:     row.GoogleMailboxScanEnabled,
		GoogleMailboxScanClientEmail: row.GoogleMailboxScanClientEmail,
		LastSyncAt:                   nullTimeString(row.LastSyncAt),
		CreatedAt:                    row.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func (a *App) listSiemDestinations(ctx context.Context, organizationID string) ([]siemDestinationRow, error) {
	rows, err := a.db.QueryContext(ctx, `
		SELECT
			id,
			kind::text,
			name,
			COALESCE(endpoint_url, ''),
			COALESCE(file_path, ''),
			COALESCE(index, ''),
			array_to_json(streams)::text,
			status::text,
			last_delivery_at,
			COALESCE(last_error, ''),
			deliveries_ok,
			deliveries_fail,
			created_at
		FROM siem_destinations
		WHERE organization_id = $1
		ORDER BY created_at DESC
	`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var destinations []siemDestinationRow
	for rows.Next() {
		var row siemDestinationRow
		var streamsJSON string
		if err := rows.Scan(
			&row.ID,
			&row.Kind,
			&row.Name,
			&row.EndpointURL,
			&row.FilePath,
			&row.Index,
			&streamsJSON,
			&row.Status,
			&row.LastDeliveryAt,
			&row.LastError,
			&row.DeliveriesOk,
			&row.DeliveriesFail,
			&row.CreatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(streamsJSON), &row.Streams)
		destinations = append(destinations, row)
	}
	return destinations, rows.Err()
}

func (row siemDestinationRow) toProto() *aperiov1.SiemDestination {
	return &aperiov1.SiemDestination{
		Id:             row.ID,
		Kind:           row.Kind,
		Name:           row.Name,
		EndpointUrl:    row.EndpointURL,
		FilePath:       row.FilePath,
		Index:          row.Index,
		Streams:        row.Streams,
		Status:         row.Status,
		LastDeliveryAt: nullTimeString(row.LastDeliveryAt),
		LastError:      row.LastError,
		DeliveriesOk:   row.DeliveriesOk,
		DeliveriesFail: row.DeliveriesFail,
		CreatedAt:      row.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func (a *App) listShadowItOauthApps(ctx context.Context, organizationID string) ([]shadowItOauthAppRow, error) {
	rows, err := a.db.QueryContext(ctx, `
		WITH grant_rollup AS (
			SELECT
				g.asset_id,
				COUNT(DISTINCT g.id)::int AS user_count,
				MAX(g.last_observed_at) AS last_observed_at,
				COALESCE(json_agg(DISTINCT scope) FILTER (WHERE scope IS NOT NULL), '[]'::json) AS scopes
			FROM oauth_app_grants g
			LEFT JOIN LATERAL unnest(g.scopes) AS scope ON TRUE
			WHERE g.organization_id = $1
			GROUP BY g.asset_id
		)
		SELECT
			sa.id,
			COALESCE(sa.provider::text, ''),
			sa.name,
			COALESCE(sa.summary, ''),
			COALESCE(sa.external_id, ''),
			array_to_json(sa.labels)::text,
			sa.criticality::text,
			sa.contains_sensitive_data,
			sa.risk_score,
			COALESCE(gr.last_observed_at, sa.last_observed_at),
			COALESCE(gr.user_count, 0),
			COALESCE(gr.scopes::text, '[]'),
			COALESCE(ic.id, ''),
			COALESCE(ic.provider::text, ''),
			COALESCE(ic.display_name, '')
		FROM security_assets sa
		LEFT JOIN integration_connections ic ON ic.id = sa.integration_id
		LEFT JOIN grant_rollup gr ON gr.asset_id = sa.id
		WHERE sa.organization_id = $1 AND sa.type = 'OAUTH_APP' AND 'shadow-it' = ANY(sa.labels)
		ORDER BY sa.risk_score DESC, sa.name ASC
	`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var apps []shadowItOauthAppRow
	for rows.Next() {
		var row shadowItOauthAppRow
		var labelsJSON, scopesJSON string
		if err := rows.Scan(
			&row.ID,
			&row.Provider,
			&row.Name,
			&row.Summary,
			&row.ExternalID,
			&labelsJSON,
			&row.Criticality,
			&row.ContainsSensitiveData,
			&row.RiskScore,
			&row.LastObservedAt,
			&row.UserCount,
			&scopesJSON,
			&row.IntegrationID,
			&row.IntegrationProvider,
			&row.IntegrationName,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(labelsJSON), &row.Labels)
		_ = json.Unmarshal([]byte(scopesJSON), &row.Scopes)
		apps = append(apps, row)
	}
	return apps, rows.Err()
}

func (row shadowItOauthAppRow) toProto() *aperiov1.ShadowItOauthApp {
	app := &aperiov1.ShadowItOauthApp{
		Id:                    row.ID,
		Provider:              row.Provider,
		Name:                  row.Name,
		Summary:               row.Summary,
		ExternalId:            row.ExternalID,
		Labels:                row.Labels,
		Criticality:           row.Criticality,
		ContainsSensitiveData: row.ContainsSensitiveData,
		RiskScore:             row.RiskScore,
		LastObservedAt:        nullTimeString(row.LastObservedAt),
		UserCount:             row.UserCount,
		Scopes:                row.Scopes,
	}
	if row.IntegrationID != "" {
		app.Integration = &aperiov1.FindingIntegration{
			Id:          row.IntegrationID,
			Provider:    row.IntegrationProvider,
			DisplayName: row.IntegrationName,
		}
	}
	return app
}

func (a *App) listShadowItOauthAppGrants(
	ctx context.Context,
	organizationID string,
	assetID string,
) (*aperiov1.ShadowItOauthAppRef, []shadowItOauthAppGrantRow, error) {
	var app aperiov1.ShadowItOauthAppRef
	if err := a.db.QueryRowContext(ctx, `
		SELECT id, name, COALESCE(external_id, ''), COALESCE(provider::text, '')
		FROM security_assets
		WHERE id = $1 AND organization_id = $2 AND type = 'OAUTH_APP'
	`, assetID, organizationID).Scan(&app.Id, &app.Name, &app.ExternalId, &app.Provider); err != nil {
		return nil, nil, err
	}
	rows, err := a.db.QueryContext(ctx, `
		SELECT
			id,
			user_email,
			COALESCE(user_external_id, ''),
			COALESCE(user_display_name, ''),
			array_to_json(scopes)::text,
			anonymous,
			native_app,
			last_observed_at
		FROM oauth_app_grants
		WHERE organization_id = $1 AND asset_id = $2
		ORDER BY user_email ASC
	`, organizationID, assetID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var grants []shadowItOauthAppGrantRow
	for rows.Next() {
		var row shadowItOauthAppGrantRow
		var scopesJSON string
		if err := rows.Scan(
			&row.ID,
			&row.UserEmail,
			&row.UserExternalID,
			&row.UserDisplayName,
			&scopesJSON,
			&row.Anonymous,
			&row.NativeApp,
			&row.LastObservedAt,
		); err != nil {
			return nil, nil, err
		}
		_ = json.Unmarshal([]byte(scopesJSON), &row.Scopes)
		grants = append(grants, row)
	}
	return &app, grants, rows.Err()
}

func (row shadowItOauthAppGrantRow) toProto() *aperiov1.ShadowItOauthAppGrant {
	return &aperiov1.ShadowItOauthAppGrant{
		Id:              row.ID,
		UserEmail:       row.UserEmail,
		UserExternalId:  row.UserExternalID,
		UserDisplayName: row.UserDisplayName,
		Scopes:          row.Scopes,
		Anonymous:       row.Anonymous,
		NativeApp:       row.NativeApp,
		LastObservedAt:  row.LastObservedAt.UTC().Format(time.RFC3339Nano),
	}
}

func nullTimeString(value sql.NullTime) string {
	if !value.Valid {
		return ""
	}
	return value.Time.UTC().Format(time.RFC3339Nano)
}

func (a *App) listSecurityAssets(
	ctx context.Context,
	organizationID string,
	req *aperiov1.ListSecurityAssetsRequest,
) ([]securityAssetRow, error) {
	args := []any{organizationID}
	conditions := []string{"sa.organization_id = $1"}
	if trimmed := strings.TrimSpace(req.Type); trimmed != "" {
		args = append(args, trimmed)
		conditions = append(conditions, "sa.type::text = $"+intPlaceholder(len(args)))
	}
	if trimmed := strings.TrimSpace(req.OwnershipStatus); trimmed != "" {
		args = append(args, trimmed)
		conditions = append(conditions, "sa.ownership_status::text = $"+intPlaceholder(len(args)))
	}
	if trimmed := strings.TrimSpace(req.IntegrationId); trimmed != "" {
		args = append(args, trimmed)
		conditions = append(conditions, "sa.integration_id = $"+intPlaceholder(len(args)))
	}
	query := `
		WITH open_findings AS (
			SELECT asset_id, COUNT(*)::int AS open_finding_count
			FROM security_findings
			WHERE organization_id = $1 AND status = 'OPEN'
			GROUP BY asset_id
		),
		active_exceptions AS (
			SELECT asset_id, COUNT(*)::int AS active_exception_count
			FROM risk_exceptions
			WHERE organization_id = $1
			  AND status = 'ACTIVE'
			  AND (expires_at IS NULL OR expires_at > NOW())
			GROUP BY asset_id
		)
		SELECT
			sa.id,
			sa.type::text,
			COALESCE(sa.provider::text, ''),
			sa.name,
			COALESCE(sa.summary, ''),
			COALESCE(sa.external_id, ''),
			array_to_json(sa.labels)::text,
			sa.criticality::text,
			sa.exposure_level::text,
			sa.ownership_status::text,
			sa.contains_sensitive_data,
			sa.is_privileged,
			sa.risk_score,
			sa.last_observed_at,
			sa.created_at,
			sa.updated_at,
			COALESCE(ic.id, ''),
			COALESCE(ic.provider::text, ''),
			COALESCE(ic.display_name, ''),
			COALESCE(owner.id, ''),
			COALESCE(owner.email, ''),
			COALESCE(owner.display_name, ''),
			COALESCE(business_owner.id, ''),
			COALESCE(business_owner.email, ''),
			COALESCE(business_owner.display_name, ''),
			COALESCE(of.open_finding_count, 0),
			COALESCE(ae.active_exception_count, 0)
		FROM security_assets sa
		LEFT JOIN integration_connections ic ON ic.id = sa.integration_id
		LEFT JOIN users owner ON owner.id = sa.owner_user_id
		LEFT JOIN users business_owner ON business_owner.id = sa.business_owner_user_id
		LEFT JOIN open_findings of ON of.asset_id = sa.id
		LEFT JOIN active_exceptions ae ON ae.asset_id = sa.id
		WHERE ` + strings.Join(conditions, " AND ") + `
		ORDER BY sa.risk_score DESC, sa.name ASC
	`
	rows, err := a.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var assets []securityAssetRow
	for rows.Next() {
		var row securityAssetRow
		var labelsJSON string
		if err := rows.Scan(
			&row.ID,
			&row.Type,
			&row.Provider,
			&row.Name,
			&row.Summary,
			&row.ExternalID,
			&labelsJSON,
			&row.Criticality,
			&row.ExposureLevel,
			&row.OwnershipStatus,
			&row.ContainsSensitiveData,
			&row.IsPrivileged,
			&row.RiskScore,
			&row.LastObservedAt,
			&row.CreatedAt,
			&row.UpdatedAt,
			&row.IntegrationID,
			&row.IntegrationProvider,
			&row.IntegrationName,
			&row.OwnerID,
			&row.OwnerEmail,
			&row.OwnerDisplayName,
			&row.BusinessOwnerID,
			&row.BusinessOwnerEmail,
			&row.BusinessOwnerName,
			&row.OpenFindingCount,
			&row.ActiveExceptionCount,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(labelsJSON), &row.Labels)
		assets = append(assets, row)
	}
	return assets, rows.Err()
}

func (row securityAssetRow) toProto() *aperiov1.SecurityAsset {
	asset := &aperiov1.SecurityAsset{
		Id:                    row.ID,
		Type:                  row.Type,
		Provider:              row.Provider,
		Name:                  row.Name,
		Summary:               row.Summary,
		ExternalId:            row.ExternalID,
		Labels:                row.Labels,
		Criticality:           row.Criticality,
		ExposureLevel:         row.ExposureLevel,
		OwnershipStatus:       row.OwnershipStatus,
		ContainsSensitiveData: row.ContainsSensitiveData,
		IsPrivileged:          row.IsPrivileged,
		RiskScore:             row.RiskScore,
		LastObservedAt:        nullTimeString(row.LastObservedAt),
		CreatedAt:             row.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt:             row.UpdatedAt.UTC().Format(time.RFC3339Nano),
		OpenFindingCount:      row.OpenFindingCount,
		ActiveExceptionCount:  row.ActiveExceptionCount,
	}
	if row.IntegrationID != "" {
		asset.Integration = &aperiov1.FindingIntegration{
			Id:          row.IntegrationID,
			Provider:    row.IntegrationProvider,
			DisplayName: row.IntegrationName,
		}
	}
	if row.OwnerID != "" {
		asset.Owner = &aperiov1.SecurityPrincipal{
			Id:          row.OwnerID,
			Email:       row.OwnerEmail,
			DisplayName: row.OwnerDisplayName,
		}
	}
	if row.BusinessOwnerID != "" {
		asset.BusinessOwner = &aperiov1.SecurityPrincipal{
			Id:          row.BusinessOwnerID,
			Email:       row.BusinessOwnerEmail,
			DisplayName: row.BusinessOwnerName,
		}
	}
	return asset
}

func (a *App) listRiskExceptions(ctx context.Context, organizationID string) ([]riskExceptionRow, error) {
	rows, err := a.db.QueryContext(ctx, `
		SELECT
			re.id,
			re.title,
			re.rationale,
			array_to_json(re.compensating_controls)::text,
			CASE
				WHEN re.status = 'ACTIVE' AND re.expires_at IS NOT NULL AND re.expires_at <= NOW()
					THEN 'EXPIRED'
				ELSE re.status::text
			END,
			re.expires_at,
			re.approved_at,
			re.created_at,
			re.updated_at,
			COALESCE(sa.id, ''),
			COALESCE(sa.name, ''),
			COALESCE(sa.type::text, ''),
			COALESCE(sf.id, ''),
			COALESCE(sf.title, ''),
			COALESCE(sf.severity::text, ''),
			COALESCE(sf.status::text, ''),
			COALESCE(created_by.id, ''),
			COALESCE(created_by.email, ''),
			COALESCE(created_by.display_name, ''),
			COALESCE(approved_by.id, ''),
			COALESCE(approved_by.email, ''),
			COALESCE(approved_by.display_name, '')
		FROM risk_exceptions re
		LEFT JOIN security_assets sa ON sa.id = re.asset_id
		LEFT JOIN security_findings sf ON sf.id = re.finding_id
		LEFT JOIN users created_by ON created_by.id = re.created_by_user_id
		LEFT JOIN users approved_by ON approved_by.id = re.approved_by_user_id
		WHERE re.organization_id = $1
		ORDER BY re.created_at DESC
	`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var exceptions []riskExceptionRow
	for rows.Next() {
		var row riskExceptionRow
		var controlsJSON string
		if err := rows.Scan(
			&row.ID,
			&row.Title,
			&row.Rationale,
			&controlsJSON,
			&row.Status,
			&row.ExpiresAt,
			&row.ApprovedAt,
			&row.CreatedAt,
			&row.UpdatedAt,
			&row.AssetID,
			&row.AssetName,
			&row.AssetType,
			&row.FindingID,
			&row.FindingTitle,
			&row.FindingSeverity,
			&row.FindingStatus,
			&row.CreatedByID,
			&row.CreatedByEmail,
			&row.CreatedByName,
			&row.ApprovedByID,
			&row.ApprovedByEmail,
			&row.ApprovedByName,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(controlsJSON), &row.CompensatingControls)
		exceptions = append(exceptions, row)
	}
	return exceptions, rows.Err()
}

func (row riskExceptionRow) toProto() *aperiov1.RiskException {
	exception := &aperiov1.RiskException{
		Id:                   row.ID,
		Title:                row.Title,
		Rationale:            row.Rationale,
		CompensatingControls: row.CompensatingControls,
		Status:               row.Status,
		ExpiresAt:            nullTimeString(row.ExpiresAt),
		ApprovedAt:           nullTimeString(row.ApprovedAt),
		CreatedAt:            row.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt:            row.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
	if row.AssetID != "" {
		exception.Asset = &aperiov1.RiskExceptionAsset{
			Id:   row.AssetID,
			Name: row.AssetName,
			Type: row.AssetType,
		}
	}
	if row.FindingID != "" {
		exception.Finding = &aperiov1.RiskExceptionFinding{
			Id:       row.FindingID,
			Title:    row.FindingTitle,
			Severity: row.FindingSeverity,
			Status:   row.FindingStatus,
		}
	}
	if row.CreatedByID != "" {
		exception.CreatedBy = &aperiov1.SecurityPrincipal{
			Id:          row.CreatedByID,
			Email:       row.CreatedByEmail,
			DisplayName: row.CreatedByName,
		}
	}
	if row.ApprovedByID != "" {
		exception.ApprovedBy = &aperiov1.SecurityPrincipal{
			Id:          row.ApprovedByID,
			Email:       row.ApprovedByEmail,
			DisplayName: row.ApprovedByName,
		}
	}
	return exception
}

// openFindings loads the same finding fields used by the TypeScript risk
// scorer. Keeping the selection explicit prevents the Go endpoint from drifting
// into raw database aggregates that do not match the product metric.
func (a *App) openFindings(ctx context.Context, organizationID string) ([]riskFinding, error) {
	rows, err := a.db.QueryContext(ctx, `
		SELECT sf.risk_score, sf.severity::text, sf.detected_at, sf.evidence, ic.provider::text
		FROM security_findings sf
		JOIN integration_connections ic ON ic.id = sf.integration_id
		WHERE sf.organization_id = $1 AND sf.status = 'OPEN'
	`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []riskFinding
	for rows.Next() {
		var finding riskFinding
		var evidenceBytes []byte
		if err := rows.Scan(
			&finding.RiskScore,
			&finding.Severity,
			&finding.DetectedAt,
			&evidenceBytes,
			&finding.Provider,
		); err != nil {
			return nil, err
		}
		if len(evidenceBytes) > 0 {
			_ = json.Unmarshal(evidenceBytes, &finding.Evidence)
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

func aggregateRiskScore(findings []riskFinding) int {
	if len(findings) == 0 {
		return 0
	}
	scores := make([]int, 0, len(findings))
	criticalCount := 0
	highCount := 0
	recentHighCount := 0
	providers := map[string]struct{}{}
	for _, finding := range findings {
		score := calculateFindingRiskScore(finding)
		scores = append(scores, score)
		if finding.Severity == "CRITICAL" {
			criticalCount++
		}
		if finding.Severity == "HIGH" {
			highCount++
		}
		if score >= 70 && time.Since(finding.DetectedAt) <= 7*24*time.Hour {
			recentHighCount++
		}
		if provider := providerFromFinding(finding); provider != "" {
			providers[provider] = struct{}{}
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(scores)))
	highest := scores[0]
	// The highest active finding dominates posture, while the weighted residual
	// captures breadth without allowing many small findings to exceed critical.
	residual := 0.0
	weights := []float64{0.2, 0.12, 0.08, 0.05}
	for index, score := range scores[1:] {
		weight := 0.03
		if index < len(weights) {
			weight = weights[index]
		}
		residual += float64(score) * weight
	}
	return clampInt(int(math.Round(
		float64(highest)*0.72+
			residual+
			float64(minInt(14, criticalCount*6+highCount*2))+
			float64(minInt(8, maxInt(0, len(providers)-1)*2))+
			float64(minInt(8, recentHighCount*2)),
	)), 0, 100)
}

func calculateFindingRiskScore(finding riskFinding) int {
	score := maxInt(clampInt(finding.RiskScore, 0, 100), severityFloor(finding.Severity))
	bonus := 0

	// Keep this Go scorer aligned with packages/shared/src/risk-scoring.ts so
	// dashboard aggregates match worker/UI risk semantics.
	grantedRole := strings.ToLower(stringEvidence(finding.Evidence, "grantedRole", "role"))
	if strings.Contains(grantedRole, "super admin") {
		bonus += 10
	} else if strings.Contains(grantedRole, "admin") {
		bonus += 6
	}
	if boolEvidenceEquals(finding.Evidence, "delegatedAdmin", true) {
		bonus += 4
	}
	if boolEvidenceEquals(finding.Evidence, "mfaEnrolled", false) {
		bonus += 10
	}
	if boolEvidenceEquals(finding.Evidence, "mfaEnforced", false) {
		bonus += 8
	}

	visibility := strings.ToLower(stringEvidence(finding.Evidence, "visibility", "exposureLevel"))
	if strings.Contains(visibility, "public") ||
		strings.Contains(visibility, "anyone") ||
		strings.Contains(visibility, "shared_externally") {
		bonus += 10
	} else if strings.Contains(visibility, "external") {
		bonus += 6
	}

	riskReason := strings.ToLower(stringEvidence(finding.Evidence, "riskReason"))
	if strings.Contains(riskReason, "full mailbox") || strings.Contains(riskReason, "mailbox-settings") {
		bonus += 8
	} else if strings.Contains(riskReason, "mailbox") {
		bonus += 4
	}

	scopeCount := numberEvidence(finding.Evidence, "scopeCount", len(stringArrayEvidence(finding.Evidence, "scopes")))
	bonus += minInt(8, maxInt(0, scopeCount-1))

	delegateCount := numberEvidence(finding.Evidence, "delegateCount", len(stringArrayEvidence(finding.Evidence, "delegates")))
	sendAsCount := numberEvidence(finding.Evidence, "sendAsCount", len(stringArrayEvidence(finding.Evidence, "sendAsAliases")))
	bonus += minInt(8, delegateCount*2+sendAsCount*2)

	if len(stringArrayEvidence(finding.Evidence, "comboKinds")) > 1 {
		bonus += 8
	}
	bonus += minInt(12, externalEmailCount(finding.Evidence)*3)

	if time.Since(finding.DetectedAt) <= 24*time.Hour {
		bonus += 4
	} else if time.Since(finding.DetectedAt) <= 7*24*time.Hour {
		bonus += 2
	} else if time.Since(finding.DetectedAt) > 90*24*time.Hour {
		bonus -= 8
	} else if time.Since(finding.DetectedAt) > 30*24*time.Hour {
		bonus -= 4
	}
	return clampInt(score+bonus, 0, 100)
}

func severityFloor(severity string) int {
	switch severity {
	case "CRITICAL":
		return 88
	case "HIGH":
		return 68
	case "MEDIUM":
		return 45
	case "LOW":
		return 25
	default:
		return 10
	}
}

func stringEvidence(evidence map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := evidence[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func boolEvidenceEquals(evidence map[string]any, key string, expected bool) bool {
	value, ok := evidence[key].(bool)
	return ok && value == expected
}

func numberEvidence(evidence map[string]any, key string, fallback int) int {
	switch value := evidence[key].(type) {
	case int:
		return value
	case int32:
		return int(value)
	case int64:
		return int(value)
	case float64:
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return fallback
		}
		return int(value)
	case json.Number:
		parsed, err := value.Int64()
		if err == nil {
			return int(parsed)
		}
	}
	return fallback
}

func stringArrayEvidence(evidence map[string]any, key string) []string {
	value, ok := evidence[key]
	if !ok {
		return nil
	}
	if entry, ok := value.(string); ok {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			return nil
		}
		return []string{trimmed}
	}
	values, ok := value.([]any)
	if !ok {
		return nil
	}
	entries := make([]string, 0, len(values))
	for _, raw := range values {
		entry, ok := raw.(string)
		if !ok {
			continue
		}
		trimmed := strings.TrimSpace(entry)
		if trimmed != "" {
			entries = append(entries, trimmed)
		}
	}
	return entries
}

func providerFromFinding(finding riskFinding) string {
	if finding.Provider != "" {
		return finding.Provider
	}
	return stringEvidence(finding.Evidence, "provider")
}

func externalEmailCount(evidence map[string]any) int {
	anchorEmail := firstString(
		stringEvidence(evidence, "mailbox"),
		stringEvidence(evidence, "user"),
		stringEvidence(evidence, "actor"),
		stringEvidence(evidence, "target"),
	)
	anchorDomain := domainFromEmail(anchorEmail)
	if anchorDomain == "" {
		return 0
	}

	candidates := append([]string{}, stringArrayEvidence(evidence, "delegates")...)
	candidates = append(candidates, stringArrayEvidence(evidence, "sendAsAliases")...)
	candidates = append(candidates, stringArrayEvidence(evidence, "externalSendAsAliases")...)
	candidates = append(candidates,
		stringEvidence(evidence, "forwardedTo"),
		stringEvidence(evidence, "recoveryEmail"),
		stringEvidence(evidence, "externalActor"),
		stringEvidence(evidence, "delegate"),
	)
	external := map[string]struct{}{}
	for _, email := range candidates {
		domain := domainFromEmail(email)
		if domain != "" && domain != anchorDomain {
			external[strings.ToLower(strings.TrimSpace(email))] = struct{}{}
		}
	}
	return len(external)
}

func firstString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func domainFromEmail(email string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(email)), "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

func clampInt(value, minValue, maxValue int) int {
	return minInt(maxInt(value, minValue), maxValue)
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

// hashOpaqueToken mirrors packages/security/src/crypto.ts. Session rows store
// only SHA-256 hashes of raw token material; the Go service must hash the cookie
// suffix before comparing it in SQL.
func hashOpaqueToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// withCORS allows the browser-based Connect client to include the HttpOnly
// session cookie. It only reflects configured web origins and treats OPTIONS as
// a transport preflight, leaving auth enforcement to individual RPCs.
func (a *App) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimRight(r.Header.Get("Origin"), "/")
		if origin != "" && a.isAllowedWebOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Headers", "authorization, content-type, connect-protocol-version, x-user-agent")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// Unsafe cookie-authenticated requests must come from the configured web
		// origin. Bearer/Connect clients without the session cookie are handled by
		// per-RPC authentication instead.
		if isUnsafeMethod(r.Method) && sessionCookie(r.Header.Get("Cookie")) != "" && !a.hasAllowedRequestOrigin(r) {
			writeError(w, http.StatusForbidden, "invalid request origin")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isUnsafeMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

func (a *App) hasAllowedRequestOrigin(r *http.Request) bool {
	origin := strings.TrimRight(r.Header.Get("Origin"), "/")
	if origin == "" {
		referer := r.Header.Get("Referer")
		if referer != "" {
			parsed, err := url.Parse(referer)
			if err == nil {
				origin = parsed.Scheme + "://" + parsed.Host
			}
		}
	}
	return origin != "" && a.isAllowedWebOrigin(origin)
}

func (a *App) isAllowedWebOrigin(origin string) bool {
	normalized := strings.TrimRight(strings.TrimSpace(origin), "/")
	for _, allowed := range strings.Split(a.cfg.WebOrigin, ",") {
		if normalized == strings.TrimRight(strings.TrimSpace(allowed), "/") {
			return true
		}
	}
	return false
}

// writeJSON is used only by non-Connect compatibility endpoints such as
// /healthz. ConnectRPC responses are encoded by the generated handlers.
func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// writeError keeps liveness and pre-Connect utility endpoints consistent with
// the existing REST API's simple {error} response shape.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
