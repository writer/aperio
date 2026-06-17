package bootstrap

import (
	"context"
	"database/sql"
	"encoding/base64"
	"net/http"
	"os"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/writer/aperio/internal/config"
)

// newSignupTestDB opens a Postgres connection for the signup tests but does
// NOT pre-seed an organization the way newTestDBApp does. Signup creates its
// own organization, so any pre-existing row would only get in the way.
func newSignupTestDB(t *testing.T) *App {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("APERIO_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("set APERIO_TEST_DATABASE_URL to run DB-backed route tests")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index + 1)
	}
	t.Setenv("APERIO_ENCRYPTION_KEY", "base64:"+base64.StdEncoding.EncodeToString(key))
	t.Cleanup(func() { _ = db.Close() })
	return NewApp(config.Config{WebOrigin: "http://localhost:3000", SessionIdleMinutes: 120}, db)
}

func TestCompatSignupSucceeds(t *testing.T) {
	app := newSignupTestDB(t)
	slug := "signup-" + strings.ToLower(randomBase36(10))
	email := "owner-" + strings.ToLower(randomBase36(8)) + "@example.com"
	t.Cleanup(func() {
		_, _ = app.db.ExecContext(context.Background(), `DELETE FROM organizations WHERE slug = $1`, slug)
	})

	out, err := app.compatSignup(context.Background(), map[string]any{
		"organizationName": "Signup Test",
		"organizationSlug": slug,
		"ownerEmail":       email,
		"password":         "Sup3rSecretPassphrase!",
	}, http.Header{})
	if err != nil {
		t.Fatalf("signup failed: %v", err)
	}
	data := dataMap(t, out)
	if data["token"] == "" || data["organization"] == nil || data["user"] == nil {
		t.Fatalf("expected populated signup payload, got %#v", data)
	}
	authContext, ok := data["authContext"].(compatSessionAuthContext)
	if !ok {
		t.Fatalf("expected signup auth context, got %#v", data["authContext"])
	}
	if authContext.Principal != email || authContext.AuthMode != "human_workspace_session" || authContext.TokenTransport != "http_only_cookie" {
		t.Fatalf("unexpected signup auth context = %#v", authContext)
	}
	if !stringSliceContains(authContext.AllowedTenants, authContext.TenantID) || !stringSliceContains(authContext.CerebroScopes, compatCerebroReadScope) {
		t.Fatalf("incomplete signup auth context = %#v", authContext)
	}
}

func TestCompatSignupReturnsAlreadyExistsForDuplicateSlug(t *testing.T) {
	app := newSignupTestDB(t)
	slug := "dup-" + strings.ToLower(randomBase36(10))
	t.Cleanup(func() {
		_, _ = app.db.ExecContext(context.Background(), `DELETE FROM organizations WHERE slug = $1`, slug)
	})

	if _, err := app.compatSignup(context.Background(), map[string]any{
		"organizationName": "Duplicate Test",
		"organizationSlug": slug,
		"ownerEmail":       "first-" + strings.ToLower(randomBase36(8)) + "@example.com",
		"password":         "Sup3rSecretPassphrase!",
	}, http.Header{}); err != nil {
		t.Fatalf("first signup failed: %v", err)
	}

	_, err := app.compatSignup(context.Background(), map[string]any{
		"organizationName": "Duplicate Test",
		"organizationSlug": slug,
		"ownerEmail":       "second-" + strings.ToLower(randomBase36(8)) + "@example.com",
		"password":         "Sup3rSecretPassphrase!",
	}, http.Header{})
	if err == nil {
		t.Fatal("expected duplicate-slug signup to error")
	}
	if code := connect.CodeOf(err); code != connect.CodeAlreadyExists {
		// A regression that drops the unique-violation guard would surface
		// here as CodeInternal with a 25P02 message, which is exactly the
		// confusing experience we are protecting against.
		t.Fatalf("expected CodeAlreadyExists, got %v (%v)", code, err)
	}
	if !strings.Contains(err.Error(), "workspace slug is already in use") {
		t.Fatalf("expected friendly slug-collision message, got %v", err)
	}
	if strings.Contains(strings.ToLower(err.Error()), "25p02") ||
		strings.Contains(strings.ToLower(err.Error()), "current transaction is aborted") {
		t.Fatalf("signup leaked the SQLSTATE 25P02 footgun: %v", err)
	}
}

// TestCompatSignupValidation pins down the public-surface validation contract
// so we never echo a raw Postgres constraint message (e.g. "value too long for
// type character varying(120)") to unauthenticated callers. Each case must:
//   - return CodeInvalidArgument
//   - return a stable, human-readable message
//   - not contain any SQLSTATE codes, the words "postgres"/"varchar", or any
//     of the offending raw input
func TestCompatSignupValidation(t *testing.T) {
	app := &App{}
	base := func() map[string]any {
		return map[string]any{
			"organizationName": "Valid Co",
			"organizationSlug": "valid-co",
			"ownerEmail":       "owner@example.com",
			"password":         "Sup3rSecretPassphrase!",
		}
	}

	cases := []struct {
		name       string
		mutate     func(map[string]any)
		wantPhrase string
	}{
		{
			name:       "oversized workspace name",
			mutate:     func(b map[string]any) { b["organizationName"] = strings.Repeat("a", 161) },
			wantPhrase: "workspace name",
		},
		{
			name:       "oversized workspace slug",
			mutate:     func(b map[string]any) { b["organizationSlug"] = strings.Repeat("a", 121) },
			wantPhrase: "workspace slug",
		},
		{
			name:       "invalid workspace slug characters",
			mutate:     func(b map[string]any) { b["organizationSlug"] = "Bad Slug!" },
			wantPhrase: "lowercase",
		},
		{
			name:       "missing workspace slug",
			mutate:     func(b map[string]any) { b["organizationSlug"] = " " },
			wantPhrase: "workspace slug",
		},
		{
			name:       "owner email missing @",
			mutate:     func(b map[string]any) { b["ownerEmail"] = "notanemail" },
			wantPhrase: "owner email",
		},
		{
			name:       "oversized owner email",
			mutate:     func(b map[string]any) { b["ownerEmail"] = strings.Repeat("a", 250) + "@example.com" },
			wantPhrase: "owner email",
		},
		{
			name:       "oversized display name",
			mutate:     func(b map[string]any) { b["ownerDisplayName"] = strings.Repeat("a", 161) },
			wantPhrase: "display name",
		},
		{
			name:       "invalid notification email",
			mutate:     func(b map[string]any) { b["notificationEmail"] = "no-at-symbol" },
			wantPhrase: "notification email",
		},
		{
			name:       "short password",
			mutate:     func(b map[string]any) { b["password"] = "tooShort" },
			wantPhrase: "password",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := base()
			tc.mutate(body)
			_, err := app.compatSignup(context.Background(), body, http.Header{})
			if err == nil {
				t.Fatal("expected validation error")
			}
			if code := connect.CodeOf(err); code != connect.CodeInvalidArgument {
				t.Fatalf("expected CodeInvalidArgument, got %v (%v)", code, err)
			}
			msg := strings.ToLower(err.Error())
			if !strings.Contains(msg, tc.wantPhrase) {
				t.Fatalf("expected message to mention %q, got %q", tc.wantPhrase, err.Error())
			}
			for _, leak := range []string{"sqlstate", "varchar", "postgres", "pgx", "value too long", "25p02", "42p08", "internal server error"} {
				if strings.Contains(msg, leak) {
					t.Fatalf("validation error leaked %q to client: %v", leak, err)
				}
			}
		})
	}
}

// TestCompatSignupAcceptsMultibyteNames pins the character-vs-byte distinction
// on the schema-mapped text fields. The Prisma columns are VarChar(160) which
// Postgres counts in characters, so an international name like 'Müller' (6
// chars, 7 UTF-8 bytes) or a 160-rune CJK name must NOT be rejected by the
// pre-DB validator. Switching utf8.RuneCountInString back to len() would
// regress this test.
func TestCompatSignupAcceptsMultibyteNames(t *testing.T) {
	cases := []struct {
		name  string
		field string
		value string
	}{
		{"european accented name", "organizationName", "Müller GmbH"},
		{"emoji-laden display name", "ownerDisplayName", strings.Repeat("é", 160)},
		{"160-character cjk workspace name", "organizationName", strings.Repeat("株", 160)},
		{"160-character cjk display name", "ownerDisplayName", strings.Repeat("株", 160)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]any{
				"organizationName": "Multibyte Co",
				"organizationSlug": "multibyte-co",
				"ownerEmail":       "owner@example.com",
				"password":         "Sup3rSecretPassphrase!",
			}
			body[tc.field] = tc.value
			if _, err := validateSignupPayload(body); err != nil {
				t.Fatalf("multibyte value rejected: %v", err)
			}
		})
	}
}

// TestCompatSignupRejectsUnicodeEmails pins the ASCII-only email shape so a
// future regression that loosens signupEmailPattern back to "any non-whitespace
// rune" cannot reintroduce the byte-vs-character footgun where an email like
// 'éééé...@ex.co' fits VARCHAR(255) by character count but trips the byte cap.
func TestCompatSignupRejectsUnicodeEmails(t *testing.T) {
	cases := []struct {
		name  string
		field string
		value string
	}{
		{"owner email with accents", "ownerEmail", "éé@example.com"},
		{"owner email with CJK", "ownerEmail", "用户@example.com"},
		{"notification email with accents", "notificationEmail", "café@example.com"},
		{"notification email with CJK", "notificationEmail", "用户@example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]any{
				"organizationName": "Valid Co",
				"organizationSlug": "valid-co",
				"ownerEmail":       "owner@example.com",
				"password":         "Sup3rSecretPassphrase!",
			}
			body[tc.field] = tc.value
			_, err := validateSignupPayload(body)
			if err == nil {
				t.Fatal("expected unicode email to be rejected")
			}
			if code := connect.CodeOf(err); code != connect.CodeInvalidArgument {
				t.Fatalf("expected CodeInvalidArgument, got %v (%v)", code, err)
			}
			if !strings.Contains(strings.ToLower(err.Error()), "email") {
				t.Fatalf("expected error to mention 'email', got %v", err)
			}
		})
	}
}

// TestCompatSignupAcceptsCommonAsciiEmails guards against an over-tight regex
// regression. Anything in the table below is a real-world address shape that
// admins legitimately use; tightening the pattern further must not break them.
func TestCompatSignupAcceptsCommonAsciiEmails(t *testing.T) {
	addresses := []string{
		"owner@example.com",
		"owner.with.dots@example.com",
		"owner+filter@example.com",
		"OWNER@example.com",
		"o@subdomain.example.co.uk",
		"plus_underscore-dash@example-domain.io",
		"a@b.cd",
		// RFC 5321 atext characters that real-world addresses use.
		"o'hara@example.com",
		"d'angelo@example.com",
		"alex!@example.com",
		"alex#tag@example.com",
		"a$ap@example.com",
		"a%b@example.com",
		"a&b@example.com",
		"alex*@example.com",
		"alex=tag@example.com",
		"alex?@example.com",
		"alex^@example.com",
		"alex`tag@example.com",
		"alex{tag}@example.com",
		"alex|tag@example.com",
		"alex~@example.com",
		"alex/tag@example.com",
	}
	for _, addr := range addresses {
		t.Run(addr, func(t *testing.T) {
			if _, err := validateSignupPayload(map[string]any{
				"organizationName": "Valid Co",
				"organizationSlug": "valid-co",
				"ownerEmail":       addr,
				"password":         "Sup3rSecretPassphrase!",
			}); err != nil {
				t.Fatalf("legitimate address rejected: %v", err)
			}
		})
	}
}

func TestCompatSignupRejectsOverMultibyteNames(t *testing.T) {
	cases := []struct {
		name  string
		field string
		value string
		want  string
	}{
		{"161-character cjk workspace name", "organizationName", strings.Repeat("株", 161), "workspace name"},
		{"161-character cjk display name", "ownerDisplayName", strings.Repeat("株", 161), "display name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]any{
				"organizationName": "Multibyte Co",
				"organizationSlug": "multibyte-co",
				"ownerEmail":       "owner@example.com",
				"password":         "Sup3rSecretPassphrase!",
			}
			body[tc.field] = tc.value
			_, err := validateSignupPayload(body)
			if err == nil {
				t.Fatal("expected over-limit multibyte value to be rejected")
			}
			if code := connect.CodeOf(err); code != connect.CodeInvalidArgument {
				t.Fatalf("expected CodeInvalidArgument, got %v (%v)", code, err)
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Fatalf("expected error to mention %q, got %v", tc.want, err)
			}
		})
	}
}
