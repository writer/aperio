package bootstrap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
)

// complianceReportPayload is the shape POSTed by the web client when
// exporting the compliance dashboard. The data is supplied by the client so
// the server stays stateless about compliance frameworks (which are mocked
// in the UI today) and just renders whatever it is given. When a real
// compliance store lands, the server can substitute its own data source
// without changing the rendering or the URL.
type complianceReportPayload struct {
	GeneratedAt  string                      `json:"generatedAt"`
	Organization string                      `json:"organization"`
	Frameworks   []complianceReportFramework `json:"frameworks"`
}

type complianceReportFramework struct {
	ID          string                  `json:"id"`
	Name        string                  `json:"name"`
	Version     string                  `json:"version"`
	Description string                  `json:"description"`
	Groups      []complianceReportGroup `json:"groups"`
}

type complianceReportGroup struct {
	ID          string                    `json:"id"`
	Title       string                    `json:"title"`
	Description string                    `json:"description"`
	Controls    []complianceReportControl `json:"controls"`
}

type complianceReportControl struct {
	ID            string `json:"id"`
	Title         string `json:"title"`
	Status        string `json:"status"`
	EvidenceCount int    `json:"evidenceCount"`
	Owner         string `json:"owner"`
}

// handleComplianceReport renders the supplied compliance dashboard snapshot
// as a PDF and streams it as an attachment. The body is intentionally
// trusted as a presentation payload: every byte that ends up in the file
// is something the operator already saw in their browser, the route is
// session-authenticated, and role-gated to OWNER/ADMIN so a viewer cannot
// reuse the surface to mint arbitrary PDFs.
func (a *App) handleComplianceReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
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

	const maxBody = 1 << 20 // 1 MiB is comfortably above the dashboard payload.
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "unable to read request body")
		return
	}
	if len(bodyBytes) > maxBody {
		writeError(w, http.StatusRequestEntityTooLarge, "payload too large")
		return
	}

	var payload complianceReportPayload
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(payload.Frameworks) == 0 {
		writeError(w, http.StatusBadRequest, "no frameworks supplied")
		return
	}

	pdfBytes, err := renderCompliancePDF(payload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "pdf render failed")
		return
	}

	filename := fmt.Sprintf("aperio-compliance-%s.pdf", time.Now().UTC().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pdfBytes)))
	w.Header().Set("Cache-Control", "private, no-store")
	_, _ = w.Write(pdfBytes)
}

func renderCompliancePDF(payload complianceReportPayload) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 18, 15)
	pdf.SetAutoPageBreak(true, 18)
	pdf.SetTitle("Aperio Compliance Report", true)
	pdf.SetAuthor("Aperio", true)
	tr := pdf.UnicodeTranslatorFromDescriptor("")

	generatedAt := strings.TrimSpace(payload.GeneratedAt)
	if generatedAt == "" {
		generatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	organization := strings.TrimSpace(payload.Organization)
	if organization == "" {
		organization = "Aperio organization"
	}

	pdf.SetFooterFunc(func() {
		pdf.SetY(-12)
		pdf.SetFont("Helvetica", "I", 8)
		pdf.SetTextColor(140, 140, 140)
		pdf.CellFormat(0, 8, tr(fmt.Sprintf("Aperio · page %d/{nb}", pdf.PageNo())), "", 0, "C", false, 0, "")
	})
	pdf.AliasNbPages("{nb}")

	pdf.AddPage()

	// Cover header. Keep the layout intentionally simple so the export
	// reads well at A4 print scale without relying on custom fonts.
	pdf.SetFont("Helvetica", "B", 22)
	pdf.SetTextColor(20, 20, 20)
	pdf.CellFormat(0, 12, tr("Compliance posture report"), "", 1, "L", false, 0, "")

	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(110, 110, 110)
	pdf.CellFormat(0, 6, tr(fmt.Sprintf("%s · generated %s", organization, generatedAt)), "", 1, "L", false, 0, "")
	pdf.Ln(4)

	overall := summarizePayload(payload)
	drawOverallSummary(pdf, tr, overall)
	pdf.Ln(4)

	for fi, framework := range payload.Frameworks {
		if fi > 0 {
			pdf.AddPage()
		}
		drawFrameworkSection(pdf, tr, framework)
	}

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("pdf output: %w", err)
	}
	return buf.Bytes(), nil
}

type complianceSummary struct {
	Pass     int
	Partial  int
	Fail     int
	NA       int
	Evidence int
	Total    int
	Score    int
}

func summarizeControls(controls []complianceReportControl) complianceSummary {
	var s complianceSummary
	for _, c := range controls {
		switch strings.ToUpper(c.Status) {
		case "PASS":
			s.Pass++
		case "PARTIAL":
			s.Partial++
		case "FAIL":
			s.Fail++
		default:
			s.NA++
		}
		s.Evidence += c.EvidenceCount
	}
	s.Total = s.Pass + s.Partial + s.Fail + s.NA
	inScope := s.Pass + s.Partial + s.Fail
	if inScope > 0 {
		s.Score = int((float64(s.Pass)+float64(s.Partial)*0.5)/float64(inScope)*100 + 0.5)
	}
	return s
}

func summarizeFramework(f complianceReportFramework) complianceSummary {
	var combined []complianceReportControl
	for _, g := range f.Groups {
		combined = append(combined, g.Controls...)
	}
	return summarizeControls(combined)
}

func summarizePayload(p complianceReportPayload) complianceSummary {
	var combined []complianceReportControl
	for _, f := range p.Frameworks {
		for _, g := range f.Groups {
			combined = append(combined, g.Controls...)
		}
	}
	return summarizeControls(combined)
}

func drawOverallSummary(pdf *fpdf.Fpdf, tr func(string) string, s complianceSummary) {
	pdf.SetFont("Helvetica", "B", 12)
	pdf.SetTextColor(20, 20, 20)
	pdf.CellFormat(0, 7, tr("Overall posture"), "", 1, "L", false, 0, "")
	pdf.Ln(1)

	// Five tiles laid out side-by-side; widths sum to printable width.
	const tileH = 22.0
	tileW := (210.0 - 15.0*2 - 4*3.0) / 5.0
	sr, sg, sb := scoreRGB(s.Score)
	tiles := []struct {
		label   string
		value   string
		r, g, b int
	}{
		{"Posture score", fmt.Sprintf("%d%%", s.Score), sr, sg, sb},
		{"Passing", fmt.Sprintf("%d", s.Pass), 34, 139, 84},
		{"Partial", fmt.Sprintf("%d", s.Partial), 200, 140, 30},
		{"Failing", fmt.Sprintf("%d", s.Fail), 198, 45, 45},
		{"Evidence", fmt.Sprintf("%d", s.Evidence), 70, 90, 130},
	}
	x0 := pdf.GetX()
	y0 := pdf.GetY()
	for i, t := range tiles {
		x := x0 + float64(i)*(tileW+3.0)
		pdf.SetXY(x, y0)
		pdf.SetDrawColor(220, 220, 220)
		pdf.SetFillColor(248, 248, 250)
		pdf.RoundedRect(x, y0, tileW, tileH, 2, "1234", "FD")

		pdf.SetXY(x+3, y0+3)
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(110, 110, 110)
		pdf.CellFormat(tileW-6, 4, tr(strings.ToUpper(t.label)), "", 0, "L", false, 0, "")

		pdf.SetXY(x+3, y0+9)
		pdf.SetFont("Helvetica", "B", 16)
		pdf.SetTextColor(t.r, t.g, t.b)
		pdf.CellFormat(tileW-6, 9, tr(t.value), "", 0, "L", false, 0, "")
	}
	pdf.SetXY(x0, y0+tileH+2)
}

func drawFrameworkSection(pdf *fpdf.Fpdf, tr func(string) string, framework complianceReportFramework) {
	s := summarizeFramework(framework)

	pdf.SetFont("Helvetica", "B", 16)
	pdf.SetTextColor(20, 20, 20)
	pdf.CellFormat(0, 9, tr(framework.Name), "", 1, "L", false, 0, "")

	pdf.SetFont("Helvetica", "I", 9)
	pdf.SetTextColor(110, 110, 110)
	pdf.CellFormat(0, 5, tr(strings.TrimSpace(framework.Version)), "", 1, "L", false, 0, "")

	if strings.TrimSpace(framework.Description) != "" {
		pdf.SetFont("Helvetica", "", 10)
		pdf.SetTextColor(60, 60, 60)
		pdf.MultiCell(0, 5, tr(framework.Description), "", "L", false)
	}
	pdf.Ln(2)

	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetTextColor(20, 20, 20)
	r, g, b := scoreRGB(s.Score)
	pdf.SetTextColor(r, g, b)
	pdf.CellFormat(40, 6, tr(fmt.Sprintf("Score: %d%%", s.Score)), "", 0, "L", false, 0, "")
	pdf.SetTextColor(60, 60, 60)
	pdf.SetFont("Helvetica", "", 9)
	pdf.CellFormat(0, 6, tr(fmt.Sprintf("Pass %d · Partial %d · Fail %d · N/A %d · Evidence %d",
		s.Pass, s.Partial, s.Fail, s.NA, s.Evidence)), "", 1, "L", false, 0, "")
	pdf.Ln(2)

	for _, group := range framework.Groups {
		drawGroupTable(pdf, tr, group)
		pdf.Ln(3)
	}
}

func drawGroupTable(pdf *fpdf.Fpdf, tr func(string) string, group complianceReportGroup) {
	gs := summarizeControls(group.Controls)
	r, g, b := scoreRGB(gs.Score)

	pdf.SetFont("Helvetica", "B", 11)
	pdf.SetTextColor(20, 20, 20)
	pdf.CellFormat(0, 6, tr(fmt.Sprintf("%s — %s", group.ID, group.Title)), "", 1, "L", false, 0, "")

	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(110, 110, 110)
	pdf.CellFormat(0, 5, tr(group.Description), "", 1, "L", false, 0, "")
	pdf.SetTextColor(r, g, b)
	pdf.SetFont("Helvetica", "", 9)
	pdf.CellFormat(0, 5, tr(fmt.Sprintf("Group score %d%% — %d pass · %d partial · %d fail · %d N/A",
		gs.Score, gs.Pass, gs.Partial, gs.Fail, gs.NA)), "", 1, "L", false, 0, "")
	pdf.Ln(1)

	// Column widths (printable width is 180mm at A4 with 15mm margins).
	cols := []struct {
		header string
		width  float64
		align  string
	}{
		{"ID", 22, "L"},
		{"Control", 95, "L"},
		{"Status", 22, "C"},
		{"Evidence", 18, "R"},
		{"Owner", 23, "L"},
	}

	pdf.SetFillColor(232, 232, 236)
	pdf.SetTextColor(50, 50, 50)
	pdf.SetFont("Helvetica", "B", 9)
	for _, c := range cols {
		pdf.CellFormat(c.width, 6, tr(c.header), "1", 0, c.align, true, 0, "")
	}
	pdf.Ln(-1)

	pdf.SetFont("Helvetica", "", 9)
	for i, ctrl := range group.Controls {
		if i%2 == 1 {
			pdf.SetFillColor(247, 247, 250)
		} else {
			pdf.SetFillColor(255, 255, 255)
		}
		pdf.SetTextColor(40, 40, 40)
		pdf.CellFormat(cols[0].width, 6, tr(ctrl.ID), "1", 0, cols[0].align, true, 0, "")
		// Truncate over-long titles so the table never wraps and breaks alignment.
		pdf.CellFormat(cols[1].width, 6, tr(truncate(ctrl.Title, 70)), "1", 0, cols[1].align, true, 0, "")

		sr, sg, sb := statusRGB(ctrl.Status)
		pdf.SetTextColor(sr, sg, sb)
		pdf.SetFont("Helvetica", "B", 9)
		pdf.CellFormat(cols[2].width, 6, tr(normalizeStatus(ctrl.Status)), "1", 0, cols[2].align, true, 0, "")
		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(40, 40, 40)

		evidence := "—"
		if ctrl.EvidenceCount > 0 {
			evidence = fmt.Sprintf("%d", ctrl.EvidenceCount)
		}
		pdf.CellFormat(cols[3].width, 6, tr(evidence), "1", 0, cols[3].align, true, 0, "")
		pdf.CellFormat(cols[4].width, 6, tr(truncate(ctrl.Owner, 18)), "1", 0, cols[4].align, true, 0, "")
		pdf.Ln(-1)
	}
}

func normalizeStatus(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "PASS":
		return "Pass"
	case "PARTIAL":
		return "Partial"
	case "FAIL":
		return "Fail"
	case "NOT_APPLICABLE", "NA", "N/A":
		return "N/A"
	default:
		return s
	}
}

func statusRGB(s string) (int, int, int) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "PASS":
		return 34, 139, 84
	case "PARTIAL":
		return 200, 140, 30
	case "FAIL":
		return 198, 45, 45
	default:
		return 130, 130, 130
	}
}

func scoreRGB(score int) (int, int, int) {
	switch {
	case score >= 85:
		return 34, 139, 84
	case score >= 60:
		return 200, 140, 30
	default:
		return 198, 45, 45
	}
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
