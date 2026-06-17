package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultReportTitleAndPeriodStart(t *testing.T) {
	t.Parallel()
	end := time.Date(2026, 6, 7, 0, 0, 0, 0, time.UTC)
	if got := defaultReportTitle("MONTH", end, "EXECUTIVE_SUMMARY"); got != "Monthly SaaS Detection & Response - June 2026" {
		t.Fatalf("month title: %q", got)
	}
	if got := defaultReportTitle("WEEK", end, "EXECUTIVE_SUMMARY"); got != "Weekly SaaS Detection & Response - week of Jun 7, 2026" {
		t.Fatalf("week title: %q", got)
	}
	if got := defaultReportTitle("QUARTER", end, "EXECUTIVE_SUMMARY"); got != "Quarterly SaaS Detection & Response - through Jun 7, 2026" {
		t.Fatalf("quarter title: %q", got)
	}
	if got := defaultPeriodStart("WEEK", end); !got.Equal(end.AddDate(0, 0, -7)) {
		t.Fatalf("week start: %v", got)
	}
	if got := defaultPeriodStart("QUARTER", end); !got.Equal(end.AddDate(0, -3, 0)) {
		t.Fatalf("quarter start: %v", got)
	}
	if got := defaultPeriodStart("MONTH", end); !got.Equal(end.AddDate(0, -1, 0)) {
		t.Fatalf("month start: %v", got)
	}
}

func TestDefaultReportTitleForGoogleWorkspaceTemplate(t *testing.T) {
	t.Parallel()
	end := time.Date(2026, 6, 7, 0, 0, 0, 0, time.UTC)
	cases := map[string]string{
		"WEEK":    "Google Workspace assessment - week of Jun 7, 2026",
		"MONTH":   "Google Workspace assessment - June 2026",
		"QUARTER": "Google Workspace assessment - through Jun 7, 2026",
		"CUSTOM":  "Google Workspace assessment - Jun 7, 2026",
	}
	for period, want := range cases {
		if got := defaultReportTitle(period, end, "GOOGLE_WORKSPACE_ASSESSMENT"); got != want {
			t.Fatalf("period %s: got %q want %q", period, got, want)
		}
	}
}

func TestValidReportTemplates(t *testing.T) {
	t.Parallel()
	if _, ok := validReportTemplates["EXECUTIVE_SUMMARY"]; !ok {
		t.Fatal("EXECUTIVE_SUMMARY must be allowed")
	}
	if _, ok := validReportTemplates["GOOGLE_WORKSPACE_ASSESSMENT"]; !ok {
		t.Fatal("GOOGLE_WORKSPACE_ASSESSMENT must be allowed")
	}
	if _, ok := validReportTemplates["NOT_A_REAL_TEMPLATE"]; ok {
		t.Fatal("unknown templates must be rejected")
	}
}

func TestParseOptionalReportTime(t *testing.T) {
	t.Parallel()
	fallback := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got, err := parseOptionalReportTime(map[string]any{}, "periodEnd", fallback)
	if err != nil || !got.Equal(fallback) {
		t.Fatalf("missing key fallback: %v / %v", got, err)
	}
	got, err = parseOptionalReportTime(map[string]any{"periodEnd": ""}, "periodEnd", fallback)
	if err != nil || !got.Equal(fallback) {
		t.Fatalf("empty string fallback: %v / %v", got, err)
	}
	if _, err := parseOptionalReportTime(map[string]any{"periodEnd": "not-a-timestamp"}, "periodEnd", fallback); err == nil {
		t.Fatal("expected invalid timestamp to error")
	}
	got, err = parseOptionalReportTime(map[string]any{"periodEnd": "2026-04-15T00:00:00Z"}, "periodEnd", fallback)
	if err != nil || got.Year() != 2026 || got.Month() != time.April {
		t.Fatalf("valid timestamp: %v / %v", got, err)
	}
}

func TestExecutiveReportArtifactRouteRejectsUnauthenticated(t *testing.T) {
	t.Parallel()
	app := &App{mux: http.NewServeMux()}
	app.mux.HandleFunc("/api/v1/admin/reports/", app.handleExecutiveReportArtifact)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/reports/rep_xyz/pdf", nil)
	rec := httptest.NewRecorder()
	app.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without session, got %d", rec.Code)
	}
}

func TestExecutiveReportArtifactRouteRejectsBadKind(t *testing.T) {
	t.Parallel()
	app := &App{mux: http.NewServeMux()}
	app.mux.HandleFunc("/api/v1/admin/reports/", app.handleExecutiveReportArtifact)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/reports/rep_xyz/csv", nil)
	rec := httptest.NewRecorder()
	app.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown artifact kind, got %d", rec.Code)
	}
}

func TestExecutiveReportArtifactRouteRejectsMethod(t *testing.T) {
	t.Parallel()
	app := &App{mux: http.NewServeMux()}
	app.mux.HandleFunc("/api/v1/admin/reports/", app.handleExecutiveReportArtifact)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/reports/rep_xyz/pdf", nil)
	rec := httptest.NewRecorder()
	app.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for non-GET method, got %d", rec.Code)
	}
}

func TestExecutiveReportArtifactRootResolvesEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	prev := os.Getenv("APERIO_REPORT_EXPORT_DIR")
	t.Setenv("APERIO_REPORT_EXPORT_DIR", tmp)
	defer os.Setenv("APERIO_REPORT_EXPORT_DIR", prev)

	got := executiveReportArtifactRoot()
	want, _ := filepath.Abs(tmp)
	gotAbs, _ := filepath.Abs(got)
	if gotAbs != want {
		t.Fatalf("expected env override %s, got %s", want, gotAbs)
	}
}

func TestExecutiveReportGeneratorCommandHonorsEnvOverride(t *testing.T) {
	t.Setenv("APERIO_REPORT_GENERATOR_CMD", "/bin/echo hello")
	name, args := executiveReportGeneratorCommand("rep_1")
	if name != "/bin/echo" {
		t.Fatalf("expected echo binary, got %s", name)
	}
	if len(args) != 2 || args[0] != "hello" || args[1] != "rep_1" {
		t.Fatalf("unexpected args: %v", args)
	}
}

func TestExecutiveReportGeneratorCommandDefault(t *testing.T) {
	t.Setenv("APERIO_REPORT_GENERATOR_CMD", "")
	name, args := executiveReportGeneratorCommand("rep_default")
	if name != "node" {
		t.Fatalf("expected node binary, got %s", name)
	}
	if len(args) != 2 || args[0] != "workers/executive-report-cli.mjs" || args[1] != "rep_default" {
		t.Fatalf("unexpected default args: %v", args)
	}
}

func TestExecutiveReportArtifactURLHonorsPublicBaseOverride(t *testing.T) {
	t.Setenv("APERIO_PUBLIC_API_BASE_URL", "https://aperio.example.com/")
	got := executiveReportArtifactURL("rep_123", "pdf")
	want := "https://aperio.example.com/api/v1/admin/reports/rep_123/pdf"
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestExecutiveReportArtifactURLFallsBackToRelative(t *testing.T) {
	t.Setenv("APERIO_PUBLIC_API_BASE_URL", "")
	got := executiveReportArtifactURL("rep_xyz", "html")
	want := "/api/v1/admin/reports/rep_xyz/html"
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestExecutiveReportArtifactRouteRejectsPathTraversalShape(t *testing.T) {
	t.Parallel()
	app := &App{mux: http.NewServeMux()}
	app.mux.HandleFunc("/api/v1/admin/reports/", app.handleExecutiveReportArtifact)

	// /api/v1/admin/reports/<id>/../../etc/passwd would have 3+ segments after
	// the prefix; the handler only accepts exactly two segments so traversal
	// attempts fall to the "not found" branch.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/reports/rep_xyz/../etc", nil)
	rec := httptest.NewRecorder()
	app.mux.ServeHTTP(rec, req)

	// Go's http.ServeMux normalizes "../" out of the path before invoking the
	// handler; it emits a 301 to the canonical path. The point of the test is
	// that the handler does not return 200 OK with the unsanitized path.
	if rec.Code == http.StatusOK {
		t.Fatalf("expected traversal-shaped path to be rejected, got 200")
	}
}
