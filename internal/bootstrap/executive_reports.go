package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"connectrpc.com/connect"
)

// executiveReportArtifactRoot is the on-disk root for rendered report files. It
// mirrors APERIO_SIEM_EXPORT_DIR semantics: a single env knob, predictable
// per-report file naming, no infrastructure dependency.
var executiveReportArtifactRoot = func() string {
	if value := strings.TrimSpace(os.Getenv("APERIO_REPORT_EXPORT_DIR")); value != "" {
		return value
	}
	return "./generated/reports"
}

// executiveReportGeneratorCommand returns the command + args the Go service
// runs to render a single report. It is configurable for tests and CI.
func executiveReportGeneratorCommand(reportID string) (string, []string) {
	if raw := strings.TrimSpace(os.Getenv("APERIO_REPORT_GENERATOR_CMD")); raw != "" {
		parts := strings.Fields(raw)
		return parts[0], append(parts[1:], reportID)
	}
	return "node", []string{"workers/executive-report-cli.mjs", reportID}
}

type executiveReportRow struct {
	ID                string
	OrganizationID    string
	RequestedByUserID sql.NullString
	Template          string
	Period            string
	PeriodStart       time.Time
	PeriodEnd         time.Time
	Title             string
	Summary           sql.NullString
	Status            string
	HTMLPath          sql.NullString
	PDFPath           sql.NullString
	KPISnapshotJSON   string
	ErrorMessage      sql.NullString
	GeneratedAt       sql.NullTime
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

var validReportTemplates = map[string]struct{}{
	"EXECUTIVE_SUMMARY":           {},
	"GOOGLE_WORKSPACE_ASSESSMENT": {},
}

func (r executiveReportRow) toResponse() map[string]any {
	var kpi any
	if r.KPISnapshotJSON != "" {
		_ = json.Unmarshal([]byte(r.KPISnapshotJSON), &kpi)
	}
	hasHTML := r.HTMLPath.Valid && r.HTMLPath.String != ""
	hasPDF := r.PDFPath.Valid && r.PDFPath.String != ""
	out := map[string]any{
		"id":              r.ID,
		"template":        r.Template,
		"period":          r.Period,
		"periodStart":     r.PeriodStart.UTC().Format(time.RFC3339Nano),
		"periodEnd":       r.PeriodEnd.UTC().Format(time.RFC3339Nano),
		"title":           r.Title,
		"status":          r.Status,
		"kpiSnapshot":     kpi,
		"hasHtml":         hasHTML,
		"hasPdf":          hasPDF,
		"createdAt":       r.CreatedAt.UTC().Format(time.RFC3339Nano),
		"updatedAt":       r.UpdatedAt.UTC().Format(time.RFC3339Nano),
		"requestedByUser": stringFromNull(r.RequestedByUserID),
	}
	// Backend owns artifact URL composition; clients render whatever the
	// service returns rather than concatenating path strings themselves.
	if hasHTML {
		out["htmlUrl"] = executiveReportArtifactURL(r.ID, "html")
	}
	if hasPDF {
		out["pdfUrl"] = executiveReportArtifactURL(r.ID, "pdf")
	}
	if r.Summary.Valid && r.Summary.String != "" {
		out["summary"] = r.Summary.String
	}
	if r.GeneratedAt.Valid {
		out["generatedAt"] = r.GeneratedAt.Time.UTC().Format(time.RFC3339Nano)
	}
	if r.ErrorMessage.Valid && r.ErrorMessage.String != "" {
		out["errorMessage"] = r.ErrorMessage.String
	}
	return out
}

func executiveReportArtifactURL(id, kind string) string {
	prefix := strings.TrimRight(strings.TrimSpace(os.Getenv("APERIO_PUBLIC_API_BASE_URL")), "/")
	if prefix == "" {
		// Relative URL keeps deployments behind reverse proxies / CDNs working
		// without explicit base-URL configuration. Browsers resolve against the
		// page's origin, which matches the Connect transport in the same way.
		return "/api/v1/admin/reports/" + id + "/" + kind
	}
	return prefix + "/api/v1/admin/reports/" + id + "/" + kind
}

func stringFromNull(value sql.NullString) any {
	if !value.Valid {
		return nil
	}
	return value.String
}

func (a *App) compatListExecutiveReports(ctx context.Context, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	rows, err := a.db.QueryContext(ctx, `
		SELECT id, organization_id, requested_by_user_id, template::text, period::text, period_start, period_end,
		       title, summary, status::text, html_path, pdf_path, COALESCE(kpi_snapshot::text, '{}'),
		       error_message, generated_at, created_at, updated_at
		FROM executive_reports
		WHERE organization_id = $1
		ORDER BY created_at DESC
		LIMIT 100
	`, auth.OrganizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var r executiveReportRow
		if err := rows.Scan(&r.ID, &r.OrganizationID, &r.RequestedByUserID, &r.Template, &r.Period,
			&r.PeriodStart, &r.PeriodEnd, &r.Title, &r.Summary, &r.Status,
			&r.HTMLPath, &r.PDFPath, &r.KPISnapshotJSON, &r.ErrorMessage,
			&r.GeneratedAt, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		out = append(out, r.toResponse())
	}
	return map[string]any{"data": out}, nil
}

func (a *App) compatGetExecutiveReport(ctx context.Context, id string, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	row, err := a.loadExecutiveReportRow(ctx, id, auth.OrganizationID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"data": row.toResponse()}, nil
}

func (a *App) loadExecutiveReportRow(ctx context.Context, id, orgID string) (executiveReportRow, error) {
	var r executiveReportRow
	err := a.db.QueryRowContext(ctx, `
		SELECT id, organization_id, requested_by_user_id, template::text, period::text, period_start, period_end,
		       title, summary, status::text, html_path, pdf_path, COALESCE(kpi_snapshot::text, '{}'),
		       error_message, generated_at, created_at, updated_at
		FROM executive_reports
		WHERE id = $1 AND organization_id = $2
	`, id, orgID).Scan(&r.ID, &r.OrganizationID, &r.RequestedByUserID, &r.Template, &r.Period,
		&r.PeriodStart, &r.PeriodEnd, &r.Title, &r.Summary, &r.Status,
		&r.HTMLPath, &r.PDFPath, &r.KPISnapshotJSON, &r.ErrorMessage,
		&r.GeneratedAt, &r.CreatedAt, &r.UpdatedAt)
	if err == sql.ErrNoRows {
		return r, connect.NewError(connect.CodeNotFound, errors.New("report not found"))
	}
	if err != nil {
		return r, connect.NewError(connect.CodeInternal, err)
	}
	return r, nil
}

// compatCreateExecutiveReport seeds a GENERATING row and spawns the renderer
// subprocess. The subprocess does the heavy lifting (data gathering, HTML
// template, headless-chromium PDF) and updates the row when finished.
func (a *App) compatCreateExecutiveReport(ctx context.Context, body map[string]any, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	period := strings.ToUpper(strings.TrimSpace(stringDefault(body, "period", "MONTH")))
	switch period {
	case "WEEK", "MONTH", "QUARTER", "CUSTOM":
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid period"))
	}
	template := strings.ToUpper(strings.TrimSpace(stringDefault(body, "template", "EXECUTIVE_SUMMARY")))
	if _, ok := validReportTemplates[template]; !ok {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid template"))
	}
	now := time.Now().UTC()
	periodEnd, err := parseOptionalReportTime(body, "periodEnd", now)
	if err != nil {
		return nil, err
	}
	periodStart, err := parseOptionalReportTime(body, "periodStart", defaultPeriodStart(period, periodEnd))
	if err != nil {
		return nil, err
	}
	if !periodStart.Before(periodEnd) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("periodStart must be before periodEnd"))
	}
	title := strings.TrimSpace(stringDefault(body, "title", defaultReportTitle(period, periodEnd, template)))
	if len(title) > 220 {
		title = title[:220]
	}

	id := compatID("rep")
	if _, err := a.db.ExecContext(ctx, `
		INSERT INTO executive_reports
		  (id, organization_id, requested_by_user_id, template, period, period_start, period_end, title, status, kpi_snapshot, created_at, updated_at)
		VALUES ($1, $2, $3, $4::"ReportTemplate", $5::"ReportPeriod", $6, $7, $8, 'GENERATING'::"ExecutiveReportStatus", '{}', NOW(), NOW())
	`, id, auth.OrganizationID, sqlNullString(auth.UserID), template, period, periodStart, periodEnd, title); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if err := a.recordReportRequested(ctx, auth, id, period, template); err != nil {
		// Audit-log failure should not block the request; surface in logs instead.
		fmt.Fprintf(os.Stderr, "executive-report audit log error: %v\n", err)
	}

	go a.runExecutiveReportGenerator(id)

	row, err := a.loadExecutiveReportRow(context.Background(), id, auth.OrganizationID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"data": row.toResponse()}, nil
}

func (a *App) compatDeleteExecutiveReport(ctx context.Context, id string, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	row, err := a.loadExecutiveReportRow(ctx, id, auth.OrganizationID)
	if err != nil {
		return nil, err
	}
	if _, err := a.db.ExecContext(ctx, `DELETE FROM executive_reports WHERE id = $1 AND organization_id = $2`, id, auth.OrganizationID); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	// Best-effort artifact cleanup; missing files are fine because the row is gone.
	if row.HTMLPath.Valid {
		_ = os.Remove(row.HTMLPath.String)
	}
	if row.PDFPath.Valid {
		_ = os.Remove(row.PDFPath.String)
	}
	a.writeCompatAudit(ctx, auth, "report.executive.delete", "executive_report", id, map[string]any{
		"title":  row.Title,
		"status": row.Status,
	})
	return map[string]any{"data": map[string]bool{"deleted": true}}, nil
}

func defaultReportTitle(period string, periodEnd time.Time, template string) string {
	if template == "GOOGLE_WORKSPACE_ASSESSMENT" {
		switch period {
		case "WEEK":
			return fmt.Sprintf("Google Workspace assessment - week of %s", periodEnd.Format("Jan 2, 2006"))
		case "QUARTER":
			return fmt.Sprintf("Google Workspace assessment - through %s", periodEnd.Format("Jan 2, 2006"))
		case "CUSTOM":
			return fmt.Sprintf("Google Workspace assessment - %s", periodEnd.Format("Jan 2, 2006"))
		default:
			return fmt.Sprintf("Google Workspace assessment - %s", periodEnd.Format("January 2006"))
		}
	}
	switch period {
	case "WEEK":
		return fmt.Sprintf("Weekly security posture - week of %s", periodEnd.Format("Jan 2, 2006"))
	case "QUARTER":
		return fmt.Sprintf("Quarterly security posture - through %s", periodEnd.Format("Jan 2, 2006"))
	case "CUSTOM":
		return fmt.Sprintf("Security posture report - %s", periodEnd.Format("Jan 2, 2006"))
	default:
		return fmt.Sprintf("Monthly security posture - %s", periodEnd.Format("January 2006"))
	}
}

func defaultPeriodStart(period string, periodEnd time.Time) time.Time {
	switch period {
	case "WEEK":
		return periodEnd.AddDate(0, 0, -7)
	case "QUARTER":
		return periodEnd.AddDate(0, -3, 0)
	default:
		return periodEnd.AddDate(0, -1, 0)
	}
}

func parseOptionalReportTime(body map[string]any, key string, fallback time.Time) (time.Time, error) {
	raw, ok := body[key]
	if !ok {
		return fallback, nil
	}
	str, ok := raw.(string)
	if !ok || strings.TrimSpace(str) == "" {
		return fallback, nil
	}
	parsed, err := time.Parse(time.RFC3339, str)
	if err != nil {
		return time.Time{}, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid %s timestamp", key))
	}
	return parsed.UTC(), nil
}

func sqlNullString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func (a *App) recordReportRequested(ctx context.Context, auth compatAuth, reportID, period, template string) error {
	metaBytes, err := json.Marshal(map[string]any{"period": period, "template": template})
	if err != nil {
		return err
	}
	_, err = a.db.ExecContext(ctx, `
		INSERT INTO tenant_audit_logs (id, organization_id, actor_user_id, action, target_type, target_id, metadata, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, NOW())
	`, compatID("log"), auth.OrganizationID, sqlNullString(auth.UserID),
		"executive_report.requested", "executive_report", reportID, string(metaBytes))
	return err
}

// runExecutiveReportGenerator fires the renderer subprocess. We swallow errors
// to stderr and persist a FAILED status on the report row so the UI can show
// the failure to operators instead of leaving them stuck on GENERATING.
func (a *App) runExecutiveReportGenerator(reportID string) {
	cmdName, args := executiveReportGeneratorCommand(reportID)
	cmd := exec.Command(cmdName, args...)
	cmd.Env = append(os.Environ(),
		"APERIO_REPORT_EXPORT_DIR="+executiveReportArtifactRoot(),
	)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "executive-report generator failed for %s: %v\n%s\n", reportID, err, string(output))
	msg := strings.TrimSpace(string(output))
	if msg == "" {
		msg = err.Error()
	}
	if len(msg) > 1000 {
		msg = msg[:1000]
	}
	_, _ = a.db.ExecContext(context.Background(), `
		UPDATE executive_reports
		SET status = 'FAILED'::"ExecutiveReportStatus", error_message = $1, updated_at = NOW()
		WHERE id = $2 AND status = 'GENERATING'::"ExecutiveReportStatus"
	`, msg, reportID)
}

// handleExecutiveReportArtifact serves the rendered HTML or PDF artifact for a
// completed report. It enforces session auth + tenant scoping just like the
// compat tunnel; the artifact is stored on the server filesystem, not the DB.
func (a *App) handleExecutiveReportArtifact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/reports/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	id, kind := parts[0], parts[1]
	if kind != "html" && kind != "pdf" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}

	auth, err := a.compatAuthFromSession(r.Context(), r.Header)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	row, err := a.loadExecutiveReportRow(r.Context(), id, auth.OrganizationID)
	if err != nil {
		writeError(w, http.StatusNotFound, "report not found")
		return
	}
	var artifactPath string
	var contentType string
	switch kind {
	case "html":
		if !row.HTMLPath.Valid || row.HTMLPath.String == "" {
			writeError(w, http.StatusNotFound, "html not yet rendered")
			return
		}
		artifactPath = row.HTMLPath.String
		contentType = "text/html; charset=utf-8"
	case "pdf":
		if !row.PDFPath.Valid || row.PDFPath.String == "" {
			writeError(w, http.StatusNotFound, "pdf not yet rendered")
			return
		}
		artifactPath = row.PDFPath.String
		contentType = "application/pdf"
	}

	// Pin reads inside the configured artifact root to prevent any path-traversal
	// abuse even though row.HTMLPath/row.PDFPath come from rows we wrote ourselves.
	rootAbs, err := filepath.Abs(executiveReportArtifactRoot())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid storage root")
		return
	}
	artifactAbs, err := filepath.Abs(artifactPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid artifact path")
		return
	}
	if !strings.HasPrefix(artifactAbs, rootAbs+string(os.PathSeparator)) && artifactAbs != rootAbs {
		writeError(w, http.StatusInternalServerError, "artifact outside storage root")
		return
	}

	f, err := os.Open(artifactAbs)
	if err != nil {
		writeError(w, http.StatusNotFound, "artifact missing")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", contentType)
	if kind == "pdf" {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.pdf"`, id))
	}
	w.Header().Set("Cache-Control", "private, no-store")
	_, _ = io.Copy(w, f)
}
