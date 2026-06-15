package googleworkspacepoller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMapEventTypeDriveExternalSharingByVisibility(t *testing.T) {
	for _, visibility := range []string{
		"shared_externally",
		"shared_with_external_user",
		"anyone_with_link",
		"anyone",
		"public_on_the_web",
	} {
		got := MapEventType("drive", "change_user_access", []reportsParameter{
			{Name: "visibility", Value: visibility},
		}, "company.com")
		if got != "EXTERNAL_SHARING_ENABLED" {
			t.Fatalf("visibility=%s: want EXTERNAL_SHARING_ENABLED, got %s", visibility, got)
		}
	}
}

func TestMapEventTypeDriveInternalShareUnmapped(t *testing.T) {
	for _, visibility := range []string{"private", "domain", "public_in_the_domain_with_link"} {
		got := MapEventType("drive", "change_user_access", []reportsParameter{
			{Name: "visibility", Value: visibility},
		}, "company.com")
		if got == "EXTERNAL_SHARING_ENABLED" {
			t.Fatalf("visibility=%s must not map to EXTERNAL_SHARING_ENABLED", visibility)
		}
	}
}

// TestMapEventTypeDriveSameDomainShareNotExternal pins the bug the reviewer
// caught: target_user_emails inside the owner's own domain must NOT be
// classified as EXTERNAL_SHARING_ENABLED, otherwise routine internal sharing
// produces HIGH-severity false positives in the downstream worker.
func TestMapEventTypeDriveSameDomainShareNotExternal(t *testing.T) {
	got := MapEventType("drive", "change_user_access", []reportsParameter{
		{Name: "target_user_emails", MultiValue: []string{"alice@company.com", "bob@company.com"}},
	}, "company.com")
	if got == "EXTERNAL_SHARING_ENABLED" {
		t.Fatalf("internal-only share must not map to EXTERNAL_SHARING_ENABLED, got %s", got)
	}
}

func TestMapEventTypeDriveCrossDomainShareIsExternal(t *testing.T) {
	got := MapEventType("drive", "change_acl_editors", []reportsParameter{
		{Name: "target_user_emails", MultiValue: []string{"alice@company.com", "partner@other.com"}},
	}, "company.com")
	if got != "EXTERNAL_SHARING_ENABLED" {
		t.Fatalf("share with at least one external recipient must map to EXTERNAL_SHARING_ENABLED, got %s", got)
	}
}

func TestMapEventTypeDriveTargetDomainParameter(t *testing.T) {
	internal := MapEventType("drive", "change_document_visibility", []reportsParameter{
		{Name: "target_domain", Value: "Company.COM"},
	}, "company.com")
	if internal == "EXTERNAL_SHARING_ENABLED" {
		t.Fatalf("same target_domain (case-insensitive) must not map to EXTERNAL_SHARING_ENABLED, got %s", internal)
	}
	external := MapEventType("drive", "change_document_visibility", []reportsParameter{
		{Name: "target_domain", Value: "partner.net"},
	}, "company.com")
	if external != "EXTERNAL_SHARING_ENABLED" {
		t.Fatalf("different target_domain must map to EXTERNAL_SHARING_ENABLED, got %s", external)
	}
}

// TestMapEventTypeDriveTargetOnlyConservativeWhenOwnerUnknown pins the
// conservative behaviour for the case where the poller could not derive
// an owner domain from the activity. Without an owner we cannot decide
// internal-vs-external, and the downstream worker does no gating of its
// own, so we MUST NOT fire EXTERNAL_SHARING_ENABLED on a target signal.
func TestMapEventTypeDriveTargetOnlyConservativeWhenOwnerUnknown(t *testing.T) {
	got := MapEventType("drive", "change_user_access", []reportsParameter{
		{Name: "target_user_emails", MultiValue: []string{"someone@anywhere.example"}},
	}, "")
	if got == "EXTERNAL_SHARING_ENABLED" {
		t.Fatalf("target signal with unknown owner must stay conservative, got %s", got)
	}
}

// TestMapEventTypeDriveVisibilityStillFiresWithoutOwner makes sure the
// conservative-when-unknown branch only suppresses target-based detection.
// Visibility transitions to public are intrinsically external regardless
// of who the owner is.
func TestMapEventTypeDriveVisibilityStillFiresWithoutOwner(t *testing.T) {
	got := MapEventType("drive", "change_document_visibility", []reportsParameter{
		{Name: "visibility", Value: "anyone_with_link"},
	}, "")
	if got != "EXTERNAL_SHARING_ENABLED" {
		t.Fatalf("visibility=anyone_with_link must fire even without owner, got %s", got)
	}
}

func TestMapEventTypeAdminSuperAdminGrant(t *testing.T) {
	got := MapEventType("admin", "assign_role", []reportsParameter{
		{Name: "ROLE_NAME", Value: "_SEED_ADMIN_ROLE"},
	}, "")
	if got != "SUPER_ADMIN_GRANTED" {
		t.Fatalf("want SUPER_ADMIN_GRANTED, got %s", got)
	}
}

func TestMapEventTypeAdminRoleGrantFallback(t *testing.T) {
	got := MapEventType("admin", "assign_role", []reportsParameter{
		{Name: "ROLE_NAME", Value: "Help Desk Admin"},
	}, "")
	if got != "ADMIN_ROLE_GRANTED" {
		t.Fatalf("want ADMIN_ROLE_GRANTED, got %s", got)
	}
}

func TestMapEventTypeTokenAuthorize(t *testing.T) {
	got := MapEventType("token", "authorize", nil, "")
	if got != "RISKY_OAUTH_GRANT" {
		t.Fatalf("want RISKY_OAUTH_GRANT, got %s", got)
	}
}

// TestMapEventTypeUnknownReturnsEmpty pins the dead-letter fix. The old
// passthrough behavior uppercased every raw Google event name (DOWNLOAD,
// VIEW, EDIT, SEARCH, ...) and the poller dutifully enqueued them as
// ingestion jobs. The ingestion worker has no evaluator for those, so
// ~84% of the Google queue ended up in DEAD_LETTER on a real tenant. The
// fix: return "" for unknown events and gate enqueueEvent on a non-empty
// mapping so the queue stays a meaningful signal instead of a noise
// channel. The mapping is the SOLE source of truth — adding a new
// evaluator just means adding a case in MapEventType.
func TestMapEventTypeUnknownReturnsEmpty(t *testing.T) {
	for _, app := range []string{"drive", "admin", "token", "login", "groups", "meet", "chat"} {
		got := MapEventType(app, "some_new_event_we_dont_evaluate", nil, "")
		if got != "" {
			t.Fatalf("application=%s unknown event must return \"\" (would otherwise dead-letter), got %q", app, got)
		}
	}
	// And the noisy real-world Drive events that triggered the bug:
	for _, raw := range []string{"download", "view", "edit", "search", "rename", "move", "create", "delete", "add_to_folder"} {
		got := MapEventType("drive", raw, nil, "company.com")
		if got != "" {
			t.Fatalf("drive event %q must return \"\" to stay out of the dead-letter queue, got %q", raw, got)
		}
	}
	// token/revoke is a real Google event but the ingestion worker has no
	// OAUTH_TOKEN_REVOKED evaluator and no allowlist entry, so it must drop
	// at the producer. A reviewer caught this leak in the original PR: the
	// case used to return "OAUTH_TOKEN_REVOKED" and every revoke was
	// immediately dead-lettered as unsupported work. Restoring the mapping
	// is fine but ONLY in the same commit that adds the evaluator and the
	// supportedIngestionEventTypes entry; this assertion forces that pairing.
	if got := MapEventType("token", "revoke", nil, ""); got != "" {
		t.Fatalf("token/revoke must return \"\" until an OAUTH_TOKEN_REVOKED evaluator exists, got %q", got)
	}
}

func TestIsExternalEmailEdgeCases(t *testing.T) {
	cases := []struct {
		email string
		owner string
		want  bool
	}{
		{"alice@company.com", "company.com", false},
		{"ALICE@Company.COM", "company.com", false},
		{"partner@other.com", "company.com", true},
		{"", "company.com", false},
		{"alice@company.com", "", false},
		{"malformed", "company.com", false},
		{"alice@", "company.com", false},
		{"   alice@company.com   ", "company.com", true}, // leading/trailing space breaks domain compare; treated external is acceptable safety bias
	}
	for _, tc := range cases {
		got := isExternalEmail(tc.email, tc.owner)
		if got != tc.want {
			t.Errorf("isExternalEmail(%q,%q)=%v want %v", tc.email, tc.owner, got, tc.want)
		}
	}
}

func FuzzMapEventTypeDriveDomainClassification(f *testing.F) {
	for _, seed := range []struct {
		owner  string
		target string
	}{
		{"company.com", "alice@company.com"},
		{"company.com", "partner@example.net"},
		{"tenant.example", "sub.tenant.example"},
	} {
		f.Add(seed.owner, seed.target)
	}
	f.Fuzz(func(t *testing.T, ownerDomain, target string) {
		ownerDomain = cleanDomainForFuzz(ownerDomain)
		if ownerDomain == "" {
			t.Skip()
		}
		targetDomain := cleanDomainForFuzz(target)
		if targetDomain == "" {
			t.Skip()
		}
		internalEmail := "user@" + ownerDomain
		internal := MapEventType("drive", "change_user_access", []reportsParameter{
			{Name: "target_user_emails", MultiValue: []string{internalEmail}},
		}, ownerDomain)
		if internal == "EXTERNAL_SHARING_ENABLED" {
			t.Fatalf("same-domain target %q must not map external for owner %q", internalEmail, ownerDomain)
		}

		externalEmail := "user@" + targetDomain
		external := MapEventType("drive", "change_user_access", []reportsParameter{
			{Name: "target_user_emails", MultiValue: []string{externalEmail}},
		}, ownerDomain)
		if !strings.EqualFold(targetDomain, ownerDomain) && external != "EXTERNAL_SHARING_ENABLED" {
			t.Fatalf("cross-domain target %q should map external for owner %q, got %q", externalEmail, ownerDomain, external)
		}

		public := MapEventType("drive", "change_document_visibility", []reportsParameter{
			{Name: "visibility", Value: "anyone_with_link"},
		}, "")
		if public != "EXTERNAL_SHARING_ENABLED" {
			t.Fatalf("public visibility must map external without owner domain, got %q", public)
		}
	})
}

func cleanDomainForFuzz(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.Trim(value, ".@")
	if value == "" || strings.ContainsAny(value, " \t\r\n/@:") || !strings.Contains(value, ".") {
		return ""
	}
	return value
}

// TestNextCursorAfterSweepPreservesOnPageCap is the regression pin for the
// reviewer-flagged data-loss bug. When listActivities returned exhausted=false,
// an earlier revision advanced the cursor to the OLDEST collected event. But
// Google's Reports API is a DESC query with startTime as a *lower bound*, so
// the next sweep with a larger startTime could never reach events older than
// that boundary — silent permanent data loss. Correct behavior is to leave
// the persisted cursor untouched on cap-hit so the older un-paged range stays
// reachable on the next sweep; the just-enqueued events idempotently no-op
// via the deterministic ingestion_jobs id.
func TestNextCursorAfterSweepPreservesOnPageCap(t *testing.T) {
	current := cursorRow{LastEventTime: time.Unix(100, 0).UTC(), LastUniqueQualifier: "q100"}
	activities := []reportsActivity{
		{EventTime: time.Unix(300, 0).UTC(), UniqueQualifier: "q300"}, // oldest collected
		{EventTime: time.Unix(400, 0).UTC(), UniqueQualifier: "q400"},
		{EventTime: time.Unix(500, 0).UTC(), UniqueQualifier: "q500"}, // newest collected
	}
	got := nextCursorAfterSweep(activities, false, current)
	if !got.LastEventTime.Equal(current.LastEventTime) || got.LastUniqueQualifier != current.LastUniqueQualifier {
		t.Fatalf("page-cap branch must NOT advance the cursor (would lose events older than q300 forever); got %+v want %+v", got, current)
	}
}

func TestNextCursorAfterSweepAdvancesOnExhausted(t *testing.T) {
	current := cursorRow{LastEventTime: time.Unix(100, 0).UTC(), LastUniqueQualifier: "q100"}
	activities := []reportsActivity{
		{EventTime: time.Unix(300, 0).UTC(), UniqueQualifier: "q300"},
		{EventTime: time.Unix(500, 0).UTC(), UniqueQualifier: "q500"}, // newest (ASC order)
	}
	got := nextCursorAfterSweep(activities, true, current)
	if !got.LastEventTime.Equal(time.Unix(500, 0).UTC()) || got.LastUniqueQualifier != "q500" {
		t.Fatalf("exhausted=true must advance cursor to newest collected; got %+v", got)
	}
}

func TestNextCursorAfterSweepEmptyKeepsCurrent(t *testing.T) {
	current := cursorRow{LastEventTime: time.Unix(100, 0).UTC(), LastUniqueQualifier: "q100"}
	got := nextCursorAfterSweep(nil, true, current)
	if !got.LastEventTime.Equal(current.LastEventTime) || got.LastUniqueQualifier != current.LastUniqueQualifier {
		t.Fatalf("empty activities must preserve cursor; got %+v", got)
	}
}

func TestCursorRowIsStrictlyAfter(t *testing.T) {
	c := cursorRow{LastEventTime: time.Unix(1000, 0).UTC(), LastUniqueQualifier: "B"}
	if c.isStrictlyAfter(time.Unix(900, 0).UTC(), "Z") {
		t.Fatal("earlier event misclassified as newer")
	}
	if !c.isStrictlyAfter(time.Unix(1100, 0).UTC(), "A") {
		t.Fatal("later event misclassified as not-newer")
	}
	if !c.isStrictlyAfter(time.Unix(1000, 0).UTC(), "C") {
		t.Fatal("same time, higher qualifier must be newer")
	}
	if c.isStrictlyAfter(time.Unix(1000, 0).UTC(), "A") {
		t.Fatal("same time, lower qualifier must NOT be newer")
	}
	if c.isStrictlyAfter(time.Unix(1000, 0).UTC(), "B") {
		t.Fatal("identical cursor must NOT be newer")
	}
	empty := cursorRow{}
	if !empty.isStrictlyAfter(time.Unix(0, 0).UTC(), "") {
		t.Fatal("zero cursor must accept anything")
	}
}

func FuzzNextCursorAfterSweepMonotonic(f *testing.F) {
	f.Add(int64(100), "q100", int64(200), "q200", int64(300), "q300", true)
	f.Add(int64(100), "q100", int64(200), "q200", int64(300), "q300", false)
	f.Fuzz(func(t *testing.T, currentSec int64, currentQ string, firstSec int64, firstQ string, secondSec int64, secondQ string, exhausted bool) {
		current := cursorRow{LastEventTime: time.Unix(currentSec, 0).UTC(), LastUniqueQualifier: currentQ}
		activities := []reportsActivity{
			{EventTime: time.Unix(firstSec, 0).UTC(), UniqueQualifier: firstQ},
			{EventTime: time.Unix(secondSec, 0).UTC(), UniqueQualifier: secondQ},
		}
		got := nextCursorAfterSweep(activities, exhausted, current)
		if !exhausted {
			if !got.LastEventTime.Equal(current.LastEventTime) || got.LastUniqueQualifier != current.LastUniqueQualifier {
				t.Fatalf("non-exhausted sweep advanced cursor: got %+v want %+v", got, current)
			}
			return
		}
		newest := activities[len(activities)-1]
		if !got.LastEventTime.Equal(newest.EventTime) || got.LastUniqueQualifier != newest.UniqueQualifier {
			t.Fatalf("exhausted sweep should advance to newest activity: got %+v want time=%s qualifier=%q", got, newest.EventTime, newest.UniqueQualifier)
		}
	})
}

func TestBuildJobPayloadFlattensParameters(t *testing.T) {
	bv := true
	payload := buildJobPayload("drive", reportsActivity{
		EventTime:       time.Unix(1700000000, 0).UTC(),
		UniqueQualifier: "abc",
		Actor:           reportsActor{Email: "alice@example.com"},
	}, reportsEvent{
		Name: "change_user_access",
		Parameters: []reportsParameter{
			{Name: "doc_title", Value: "Board Deck"},
			{Name: "doc_id", Value: "1xyz"},
			{Name: "visibility", Value: "shared_externally"},
			{Name: "owner_is_team_drive", BoolValue: &bv},
			{Name: "shared_with", MultiValue: []string{"bob@partner.com"}},
		},
	}, "example.com")
	params, ok := payload["parameters"].(map[string]any)
	if !ok {
		t.Fatal("parameters missing or wrong type")
	}
	if params["doc_title"] != "Board Deck" {
		t.Fatalf("doc_title not flattened: %v", params)
	}
	if params["owner_is_team_drive"] != true {
		t.Fatalf("bool param not preserved: %v", params)
	}
	if mv, ok := params["shared_with"].([]string); !ok || len(mv) != 1 || mv[0] != "bob@partner.com" {
		t.Fatalf("multi value not preserved: %v", params)
	}
	if payload["sourceEventId"] != "abc" {
		t.Fatalf("sourceEventId not derived from uniqueQualifier: %v", payload["sourceEventId"])
	}
	if payload["ownerDomain"] != "example.com" {
		t.Fatalf("ownerDomain not propagated: %v", payload["ownerDomain"])
	}
	resource, ok := payload["resource"].(map[string]any)
	if !ok || resource["name"] != "Board Deck" || resource["id"] != "1xyz" {
		t.Fatalf("resource not derived: %v", payload["resource"])
	}
}

func TestGoogleWorkspaceLegacyJobIDPreservesUpgradeIdempotency(t *testing.T) {
	got := googleWorkspaceLegacyJobID(
		reportsActivity{UniqueQualifier: "same-google-qualifier"},
		reportsEvent{Name: "change_user_access"},
	)
	want := "ijb_same-google-qualifier_change_user_access"
	if got != want {
		t.Fatalf("legacy job id = %s, want %s", got, want)
	}
}

func TestGoogleWorkspaceScopedJobIDScopesDedupeByTenantIntegrationSourceAndApplication(t *testing.T) {
	baseInteg := integrationRow{ID: "int_1", OrganizationID: "org_1"}
	baseActivity := reportsActivity{UniqueQualifier: "same-google-qualifier"}
	baseEvent := reportsEvent{Name: "change_user_access"}
	baseSource := googleReportsQueueSource("drive")
	baseID := googleWorkspaceScopedJobID(baseInteg, baseSource, "drive", baseActivity, baseEvent)

	cases := map[string]string{
		"same input":             googleWorkspaceScopedJobID(baseInteg, baseSource, "drive", baseActivity, baseEvent),
		"different org":          googleWorkspaceScopedJobID(integrationRow{ID: "int_1", OrganizationID: "org_2"}, baseSource, "drive", baseActivity, baseEvent),
		"different integ":        googleWorkspaceScopedJobID(integrationRow{ID: "int_2", OrganizationID: "org_1"}, baseSource, "drive", baseActivity, baseEvent),
		"different queue source": googleWorkspaceScopedJobID(baseInteg, googleBigQueryQueueSource("drive"), "drive", baseActivity, baseEvent),
		"different app":          googleWorkspaceScopedJobID(baseInteg, googleReportsQueueSource("admin"), "admin", baseActivity, baseEvent),
		"different event":        googleWorkspaceScopedJobID(baseInteg, baseSource, "drive", baseActivity, reportsEvent{Name: "change_document_visibility"}),
		"different source event": googleWorkspaceScopedJobID(baseInteg, baseSource, "drive", reportsActivity{UniqueQualifier: "other-google-qualifier"}, baseEvent),
	}

	if cases["same input"] != baseID {
		t.Fatalf("same inputs must produce stable job id: %s vs %s", cases["same input"], baseID)
	}
	for label, got := range cases {
		if label == "same input" {
			continue
		}
		if got == baseID {
			t.Fatalf("%s must not collide with base job id %s", label, baseID)
		}
	}
}

func TestGoogleWorkspaceQueueSourcesSeparateReportsAndBigQuery(t *testing.T) {
	if got := googleReportsQueueSource("drive"); got != "google.reports.drive" {
		t.Fatalf("reports queue source = %q", got)
	}
	if got := googleBigQueryQueueSource("drive"); got != "google.bigquery.drive" {
		t.Fatalf("BigQuery queue source = %q", got)
	}
	if googleReportsQueueSource("drive") == googleBigQueryQueueSource("drive") {
		t.Fatal("Reports and BigQuery streams must not share ingestion queue attribution")
	}
}

func TestResolveOwnerDomainPrefersDriveOwnerParam(t *testing.T) {
	got := resolveOwnerDomain(
		integrationRow{ExternalAccountID: "tenant.example"},
		reportsActivity{Actor: reportsActor{Email: "actor@actor.example"}},
		[]reportsParameter{{Name: "owner", Value: "doc.owner@docs.example"}},
	)
	if got != "docs.example" {
		t.Fatalf("expected parameters.owner to win, got %s", got)
	}
}

func TestResolveOwnerDomainFallsBackToActorThenIntegration(t *testing.T) {
	got := resolveOwnerDomain(
		integrationRow{ExternalAccountID: "tenant.example"},
		reportsActivity{Actor: reportsActor{Email: "actor@actor.example"}},
		nil,
	)
	if got != "actor.example" {
		t.Fatalf("expected actor email domain when owner param missing, got %s", got)
	}
	got = resolveOwnerDomain(
		integrationRow{ExternalAccountID: "tenant.example"},
		reportsActivity{},
		nil,
	)
	if got != "tenant.example" {
		t.Fatalf("expected ExternalAccountID fallback when actor missing, got %s", got)
	}
}

type fakeResolver struct{}

func (fakeResolver) ResolveGoogleOAuthClient(_ context.Context, _ string) (OAuthConfig, bool) {
	return OAuthConfig{ClientID: "cid", ClientSecret: "csecret"}, true
}

// TestExchangeRefreshToken pins the token-exchange wire shape so a future
// regression that drops grant_type or client_secret is caught without
// hitting real Google.
func TestExchangeRefreshToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		for _, f := range []string{"client_id", "client_secret", "refresh_token", "grant_type"} {
			if r.PostForm.Get(f) == "" {
				t.Errorf("missing form field %s", f)
			}
		}
		if got := r.PostForm.Get("grant_type"); got != "refresh_token" {
			t.Errorf("grant_type=%s, want refresh_token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"ya29.fake","expires_in":3600}`))
	}))
	defer server.Close()

	p := New(nil, fakeResolver{})
	p.httpClient = server.Client()
	p.httpClient.Transport = rewriteHostRoundTripper{target: server.URL, path: "/"}
	access, err := p.exchangeRefreshToken(context.Background(), OAuthConfig{ClientID: "cid", ClientSecret: "csecret"}, "1//refresh")
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
	if access != "ya29.fake" {
		t.Fatalf("unexpected access token: %s", access)
	}
}

// TestListActivitiesPaginatesUntilCursor pins the P1 fix: the poller must
// walk nextPageToken pages until either Google runs out of items or it
// returns an item at-or-before the persisted cursor. A future regression
// that drops pagination (or re-introduces the silent maxActivities truncation)
// breaks this test loud.
func TestListActivitiesPaginatesUntilCursor(t *testing.T) {
	// Three pages, newest → oldest, DESC order. Cursor is at time=200, so the
	// poller should fetch pages 1+2 and stop mid-page-2 when it sees time=200.
	pages := []reportsResponse{
		{
			Items: []struct {
				ID struct {
					Time            time.Time `json:"time"`
					UniqueQualifier string    `json:"uniqueQualifier"`
					ApplicationName string    `json:"applicationName"`
					CustomerID      string    `json:"customerId"`
				} `json:"id"`
				Actor  reportsActor   `json:"actor"`
				Events []reportsEvent `json:"events"`
			}{
				makeItem(500, "q500"),
				makeItem(400, "q400"),
			},
			NextPageToken: "page2",
		},
		{
			Items: []struct {
				ID struct {
					Time            time.Time `json:"time"`
					UniqueQualifier string    `json:"uniqueQualifier"`
					ApplicationName string    `json:"applicationName"`
					CustomerID      string    `json:"customerId"`
				} `json:"id"`
				Actor  reportsActor   `json:"actor"`
				Events []reportsEvent `json:"events"`
			}{
				makeItem(300, "q300"),
				makeItem(200, "q200"), // cursor; poller must stop here
				makeItem(100, "q100"), // never reached
			},
			NextPageToken: "page3",
		},
	}
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idx := atomic.AddInt32(&hits, 1) - 1
		if int(idx) >= len(pages) {
			t.Fatalf("server called more times than expected: %d", hits)
		}
		page := pages[idx]
		// Sanity-check that the second call uses the page token we sent.
		if idx == 1 && r.URL.Query().Get("pageToken") != "page2" {
			t.Errorf("expected pageToken=page2 on second call, got %q", r.URL.Query().Get("pageToken"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer server.Close()

	p := New(nil, fakeResolver{})
	p.httpClient = server.Client()
	p.httpClient.Transport = rewriteHostRoundTripper{target: server.URL, path: "/"}

	cursor := cursorRow{LastEventTime: time.Unix(200, 0).UTC(), LastUniqueQualifier: "q200"}
	activities, exhausted, err := p.listActivities(context.Background(), "drive", "tok", time.Unix(0, 0).UTC(), cursor)
	if err != nil {
		t.Fatalf("listActivities: %v", err)
	}
	if !exhausted {
		t.Fatal("expected exhausted=true when cursor reached mid-page")
	}
	if hits != 2 {
		t.Fatalf("expected exactly 2 page fetches, got %d", hits)
	}
	if len(activities) != 3 {
		t.Fatalf("expected 3 activities strictly after cursor, got %d (%v)", len(activities), qualifiers(activities))
	}
	for _, want := range []string{"q500", "q400", "q300"} {
		found := false
		for _, a := range activities {
			if a.UniqueQualifier == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %s in collected activities (%v)", want, qualifiers(activities))
		}
	}
}

// TestListActivitiesHitsPageCap pins the safety bound: if Google keeps
// returning nextPageToken indefinitely and we never reach the cursor, the
// poller stops at maxPages and reports exhausted=false so the caller knows
// to advance the cursor only to the OLDEST processed event.
func TestListActivitiesHitsPageCap(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idx := atomic.AddInt32(&hits, 1) - 1
		// Each page returns one item with a unique time strictly newer than
		// the cursor, plus a next page token so the loop never naturally ends.
		t := int64(1000 - idx)
		page := reportsResponse{NextPageToken: "more"}
		page.Items = append(page.Items, makeItem(t, "q"+strconvI(int(t))))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer server.Close()

	p := New(nil, fakeResolver{}).WithMaxPages(5)
	p.httpClient = server.Client()
	p.httpClient.Transport = rewriteHostRoundTripper{target: server.URL, path: "/"}

	activities, exhausted, err := p.listActivities(context.Background(), "drive", "tok", time.Unix(0, 0).UTC(), cursorRow{})
	if err != nil {
		t.Fatalf("listActivities: %v", err)
	}
	if exhausted {
		t.Fatal("expected exhausted=false when page cap hit")
	}
	if int(hits) != 5 {
		t.Fatalf("expected exactly 5 page fetches (the cap), got %d", hits)
	}
	if len(activities) != 5 {
		t.Fatalf("expected 5 activities, got %d", len(activities))
	}
}

func qualifiers(activities []reportsActivity) []string {
	out := make([]string, 0, len(activities))
	for _, a := range activities {
		out = append(out, a.UniqueQualifier)
	}
	return out
}

func makeItem(timeSeconds int64, qualifier string) struct {
	ID struct {
		Time            time.Time `json:"time"`
		UniqueQualifier string    `json:"uniqueQualifier"`
		ApplicationName string    `json:"applicationName"`
		CustomerID      string    `json:"customerId"`
	} `json:"id"`
	Actor  reportsActor   `json:"actor"`
	Events []reportsEvent `json:"events"`
} {
	var item struct {
		ID struct {
			Time            time.Time `json:"time"`
			UniqueQualifier string    `json:"uniqueQualifier"`
			ApplicationName string    `json:"applicationName"`
			CustomerID      string    `json:"customerId"`
		} `json:"id"`
		Actor  reportsActor   `json:"actor"`
		Events []reportsEvent `json:"events"`
	}
	item.ID.Time = time.Unix(timeSeconds, 0).UTC()
	item.ID.UniqueQualifier = qualifier
	item.Actor.Email = "actor@example.com"
	return item
}

// rewriteHostRoundTripper redirects requests to a single httptest server so
// we do not have to monkey-patch the const reportsBaseURL / tokenURL just
// for tests. path overrides the request path so each test can choose what
// the fake server is meant to be (token endpoint vs reports endpoint).
type rewriteHostRoundTripper struct {
	target string
	path   string
}

func (r rewriteHostRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	idx := strings.Index(r.target, "://")
	scheme := "http"
	host := r.target
	if idx >= 0 {
		scheme = r.target[:idx]
		host = r.target[idx+3:]
	}
	req.URL.Scheme = scheme
	req.URL.Host = host
	if r.path != "" {
		req.URL.Path = r.path
	}
	return http.DefaultTransport.RoundTrip(req)
}

func TestWakeIntegrationEmptyIDIsNoop(t *testing.T) {
	// WakeIntegration must tolerate stray empty notification payloads
	// without panicking or hitting the database; the LISTEN goroutine in
	// cmd/google-workspace-poller relies on this to swallow malformed
	// pg_notify payloads that survived the trim guard.
	p := New(nil, nil)
	if err := p.WakeIntegration(context.Background(), ""); err != nil {
		t.Fatalf("WakeIntegration(\"\") returned err: %v", err)
	}
	if err := p.WakeIntegration(context.Background(), "   "); err != nil {
		t.Fatalf("WakeIntegration(whitespace) returned err: %v", err)
	}
}
