package googleworkspacepoller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBigQueryActivityTableUsesViewDataset(t *testing.T) {
	cfg := BigQueryConfig{
		ProjectID:    "example-project",
		RawDatasetID: "workspace_logs",
		DatasetID:    "aperio_workspace_views",
		AccessMode:   "views",
	}
	if got := cfg.activityTable(); got != "aperio_activity" {
		t.Fatalf("unexpected view activity table: %s", got)
	}
	query, err := cfg.activityQuery("drive", 500)
	if err != nil {
		t.Fatalf("activityQuery: %v", err)
	}
	if !strings.Contains(query, "TIMESTAMP_TRUNC(@from_partition, DAY)") {
		t.Fatalf("query must use partition predicate for bounded scans: %s", query)
	}
	if !strings.Contains(query, "t.aperio_partition_time") || strings.Contains(query, "t._PARTITIONTIME") {
		t.Fatalf("view mode must use the safe authorized-view partition alias: %s", query)
	}
	if !strings.Contains(query, "ORDER BY CASE") || !strings.Contains(query, "time_usec_int > @cursor_usec") || !strings.Contains(query, "row_hash > @cursor_hash") {
		t.Fatalf("query must prioritize rows after the saved cursor without filtering out the overlap window: %s", query)
	}
	if strings.Contains(query, "WHERE @cursor_usec") {
		t.Fatalf("query must not filter out the late-lookback overlap window: %s", query)
	}
	if !strings.Contains(query, "record_type = @record_type") {
		t.Fatalf("query must filter by record_type: %s", query)
	}
}

func TestQueryActivityRowsPaginatesWithGetQueryResults(t *testing.T) {
	raw := `{"drive":{"target_user_emails":["external@partner.test"]}}`
	postCalls := 0
	getCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPost:
			postCalls++
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode query body: %v", err)
			}
			if _, ok := body["pageToken"]; ok {
				t.Fatalf("jobs.query request must not include pageToken")
			}
			if got := body["maxResults"]; got != float64(1) {
				t.Fatalf("maxResults=%v", got)
			}
			params := body["queryParameters"].([]any)
			paramNames := map[string]bool{}
			for _, param := range params {
				paramNames[param.(map[string]any)["name"].(string)] = true
			}
			for _, name := range []string{"cursor_usec", "cursor_hash"} {
				if !paramNames[name] {
					t.Fatalf("query parameter %s was not sent: %#v", name, params)
				}
			}
			_, _ = w.Write([]byte(bigQueryActivityFixture("next-page", "job-1", raw, "row-1", "1710000000000000")))
		case http.MethodGet:
			getCalls++
			if !strings.HasSuffix(r.URL.Path, "/projects/example-project/queries/job-1") {
				t.Fatalf("unexpected getQueryResults path: %s", r.URL.Path)
			}
			if got := r.URL.Query().Get("pageToken"); got != "next-page" {
				t.Fatalf("pageToken=%q", got)
			}
			_, _ = w.Write([]byte(bigQueryActivityFixture("", "job-1", raw, "row-2", "1710000000000001")))
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	}))
	defer server.Close()

	poller := NewBigQueryPoller(nil).
		WithHTTPClient(server.Client()).
		WithBigQueryBaseURL(server.URL).
		WithPageSize(1).
		WithMaxPages(3)
	cfg := BigQueryConfig{
		ProjectID:  "example-project",
		DatasetID:  "aperio_workspace_views",
		Location:   "US",
		AccessMode: "views",
	}

	rows, exhausted, err := poller.queryActivityRows(t.Context(), cfg, "token", "drive", time.Unix(0, 0), bigQueryCursor{})
	if err != nil {
		t.Fatalf("queryActivityRows: %v", err)
	}
	if !exhausted {
		t.Fatalf("expected pagination to exhaust")
	}
	if postCalls != 1 || getCalls != 1 {
		t.Fatalf("expected 1 jobs.query and 1 getQueryResults call, got post=%d get=%d", postCalls, getCalls)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}
}

func TestBigQueryCursorAdvancesAfterProcessedRowsEvenWhenWindowIsCapped(t *testing.T) {
	oldTime := time.Unix(100, 0).UTC()
	newTime := time.Unix(200, 0).UTC()
	cursor := bigQueryCursor{LastEventTime: oldTime, LastRowHash: "old"}
	next := cursor.advanceTo(bigQueryActivityRow{EventTime: newTime, RowHash: "new"})

	if !next.LastEventTime.Equal(newTime) || next.LastRowHash != "new" {
		t.Fatalf("cursor must advance to newest processed row, got %#v", next)
	}
}

func TestBigQueryCursorStaysPutWhenNoRowsProcessed(t *testing.T) {
	oldTime := time.Unix(100, 0).UTC()
	cursor := bigQueryCursor{LastEventTime: oldTime, LastRowHash: "old"}
	next := cursor.advanceTo(bigQueryActivityRow{})

	if !next.LastEventTime.Equal(oldTime) || next.LastRowHash != "old" {
		t.Fatalf("cursor must stay put when no rows were processed, got %#v", next)
	}
}

func TestBigQueryActivityTableUsesRawDatasetInDatasetMode(t *testing.T) {
	cfg := BigQueryConfig{
		ProjectID:    "example-project",
		RawDatasetID: "workspace_logs",
		DatasetID:    "workspace_logs",
		AccessMode:   "dataset",
	}
	if got := cfg.activityTable(); got != "activity" {
		t.Fatalf("unexpected dataset activity table: %s", got)
	}
	query, err := cfg.activityQuery("drive", 500)
	if err != nil {
		t.Fatalf("activityQuery: %v", err)
	}
	if !strings.Contains(query, "t._PARTITIONTIME") {
		t.Fatalf("dataset mode must use the native partition pseudocolumn: %s", query)
	}
}

func bigQueryActivityFixture(pageToken, jobID, rawJSON, rowHash, timeUsec string) string {
	pageTokenField := ""
	if pageToken != "" {
		pageTokenField = `"pageToken": ` + strconv.Quote(pageToken) + `,`
	}
	return `{
	  "jobComplete": true,
	  ` + pageTokenField + `
	  "jobReference": {"projectId": "example-project", "jobId": ` + strconv.Quote(jobID) + `, "location": "US"},
	  "schema": {"fields": [
	    {"name": "row_json"},
	    {"name": "row_hash"},
	    {"name": "time_usec"},
	    {"name": "record_type"},
	    {"name": "event_name"},
	    {"name": "event_type"},
	    {"name": "email"},
	    {"name": "ip_address"}
	  ]},
	  "rows": [{"f": [
	    {"v": ` + strconv.Quote(rawJSON) + `},
	    {"v": ` + strconv.Quote(rowHash) + `},
	    {"v": ` + strconv.Quote(timeUsec) + `},
	    {"v": "drive"},
	    {"v": "change_user_access"},
	    {"v": ""},
	    {"v": "owner@example.com"},
	    {"v": "203.0.113.10"}
	  ]}]
	}`
}

func TestBigQueryRowToReportsActivityNormalizesEvents(t *testing.T) {
	row := bigQueryActivityRow{
		RecordType: "drive",
		EventTime:  time.UnixMicro(1710000000000000).UTC(),
		EventName:  "change_user_access",
		Email:      "owner@example.com",
		RowHash:    "abc123",
		Raw: map[string]any{
			"drive": map[string]any{
				"target_user_emails": []any{"external@partner.test"},
			},
		},
	}

	activity, event, err := row.toReportsActivity()
	if err != nil {
		t.Fatalf("toReportsActivity: %v", err)
	}
	if activity.Actor.Email != "owner@example.com" {
		t.Fatalf("actor email=%q", activity.Actor.Email)
	}
	if event.Name != "change_user_access" {
		t.Fatalf("event name=%q", event.Name)
	}
	if len(event.Parameters) != 1 || len(event.Parameters[0].MultiValue) != 1 {
		t.Fatalf("expected normalized multiValue parameter: %#v", event.Parameters)
	}
}

func TestParseBigQueryActivityRows(t *testing.T) {
	raw := map[string]any{
		"id": map[string]any{
			"applicationName": "admin",
			"time":            "2024-03-09T16:00:00Z",
		},
		"events": []any{map[string]any{"name": "assign_role"}},
	}
	rawJSON, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var resp bigQueryQueryResponse
	fixture := `{
	  "jobComplete": true,
	  "schema": {"fields": [
	    {"name": "row_json"},
	    {"name": "row_hash"},
	    {"name": "time_usec"},
	    {"name": "record_type"},
	    {"name": "event_name"},
	    {"name": "event_type"},
	    {"name": "email"},
	    {"name": "ip_address"}
	  ]},
	  "rows": [{"f": [
	    {"v": ` + strconv.Quote(string(rawJSON)) + `},
	    {"v": "row-hash"},
	    {"v": "1710000000000000"},
	    {"v": "admin"},
	    {"v": "assign_role"},
	    {"v": ""},
	    {"v": "admin@example.com"},
	    {"v": "203.0.113.10"}
	  ]}]
	}`
	if err := json.Unmarshal([]byte(fixture), &resp); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	rows, err := decodeBigQueryActivityRows(resp)
	if err != nil {
		t.Fatalf("decodeBigQueryActivityRows: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one row, got %d", len(rows))
	}
	if rows[0].RecordType != "admin" || rows[0].RowHash != "row-hash" {
		t.Fatalf("unexpected row metadata: %#v", rows[0])
	}
	if rows[0].Raw["events"] == nil {
		t.Fatalf("expected raw event payload to be preserved")
	}
}
