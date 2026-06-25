package cerebroclaims

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/writer/aperio/internal/cerebroclient"
	sdkclaims "github.com/writer/cerebro/sdk/go/cerebroapi/claims"
	cerebrov1 "github.com/writer/cerebro/sdk/go/cerebroapi/genproto/cerebro/v1"
)

type Payload struct {
	Kind       string
	OccurredAt string
	Record     map[string]any
}

type BuildInput struct {
	// TenantID is the Cerebro tenant id used in URNs. OrganizationID remains
	// available for compatibility with older Aperio-owned claim paths.
	TenantID       string
	OrganizationID string
	RuntimeID      string
	Payload        Payload
}

func Build(input BuildInput) ([]cerebroclient.Claim, error) {
	organizationID := strings.TrimSpace(input.OrganizationID)
	tenantID := strings.TrimSpace(input.TenantID)
	if tenantID == "" {
		tenantID = organizationID
	}
	runtimeID := strings.TrimSpace(input.RuntimeID)
	if runtimeID == "" {
		return nil, errors.New("Cerebro source runtime ID is not configured")
	}
	provider := firstString(input.Payload.Record["provider"])
	if provider == "" {
		provider = "APERIO"
	}
	title := firstString(input.Payload.Record["title"])
	if title == "" {
		title = input.Payload.Kind + " from Aperio"
	}
	findingID := firstString(input.Payload.Record["dedupeKey"], input.Payload.Record["sourceEventId"])
	if findingID == "" {
		sum := hmac.New(sha256.New, []byte(organizationID))
		encoded, _ := json.Marshal(input.Payload.Record)
		_, _ = sum.Write(encoded)
		findingID = hex.EncodeToString(sum.Sum(nil))
	}
	targetLabel := firstString(input.Payload.Record["target"])
	if targetLabel == "" {
		targetLabel = title
	}
	integrationID := firstString(input.Payload.Record["integrationId"])
	if integrationID == "" {
		integrationID = "aperio"
	}

	finding := Ref(tenantID, runtimeID, "finding", findingID, title)
	target := Ref(tenantID, runtimeID, "asset", provider+":"+targetLabel, targetLabel)
	integration := Ref(tenantID, runtimeID, "integration", integrationID, provider)
	attributes := map[string]string{
		"aperio_schema": schemaVersion(input.Payload.Kind),
		"aperio_kind":   input.Payload.Kind,
	}
	for _, key := range []string{"ruleId", "dedupeKey", "sourceEventId", "source", "eventType"} {
		if value := firstString(input.Payload.Record[key]); value != "" {
			attributes[key] = value
		}
	}
	claims := []cerebroclient.Claim{
		sdkclaims.Exists(finding, claimSource(input.Payload, attributes)),
		sdkclaims.Exists(target, claimSource(input.Payload, map[string]string{"provider": provider})),
		sdkclaims.Exists(integration, claimSource(input.Payload, map[string]string{"provider": provider})),
		sdkclaims.Relation(finding, "affects", target, claimSource(input.Payload, nil)),
		sdkclaims.Relation(finding, "observed_by", integration, claimSource(input.Payload, nil)),
		sdkclaims.Attribute(finding, "title", title, claimSource(input.Payload, nil)),
		sdkclaims.Attribute(finding, "provider", provider, claimSource(input.Payload, nil)),
	}
	claims = appendOAuthGrantClaims(claims, input, finding, integration, provider)
	for _, key := range []string{"severity", "riskScore", "status", "ruleId"} {
		if value := firstString(input.Payload.Record[key]); value != "" {
			claims = append(claims, sdkclaims.Attribute(finding, key, value, claimSource(input.Payload, nil)))
		}
	}
	if description := firstString(input.Payload.Record["description"]); description != "" {
		claims = append(claims, sdkclaims.Attribute(finding, "description", description, claimSource(input.Payload, nil)))
	}
	return claims, nil
}

func appendOAuthGrantClaims(claims []cerebroclient.Claim, input BuildInput, finding, integration cerebroclient.EntityRef, provider string) []cerebroclient.Claim {
	record := input.Payload.Record
	appID := firstString(record["oauthAppId"], record["oauthClientId"], record["clientId"], record["externalAppId"])
	appName := firstString(record["oauthAppName"], record["oauthApp"], record["appName"], record["app"])
	if appID == "" && appName == "" {
		return claims
	}
	if appID == "" {
		appID = appName
	}
	if appName == "" {
		appName = appID
	}
	tenantID := strings.TrimSpace(input.TenantID)
	if tenantID == "" {
		tenantID = strings.TrimSpace(input.OrganizationID)
	}
	app := Ref(tenantID, input.RuntimeID, "oauth_app", provider+":"+appID, appName)
	grantID := firstString(record["oauthGrantId"])
	userID := firstString(record["oauthUserId"], record["userExternalId"], record["oauthUserEmail"], record["userEmail"], record["actor"])
	if grantID == "" {
		grantID = provider + ":" + appID
		if userID != "" {
			grantID += ":" + userID
		}
	}
	grantLabel := "OAuth grant for " + appName
	if user := firstString(record["oauthUserEmail"], record["userEmail"], record["actor"]); user != "" {
		grantLabel += " by " + user
	}
	grant := Ref(tenantID, input.RuntimeID, "oauth_grant", grantID, grantLabel)
	source := claimSource(input.Payload, map[string]string{
		"aperio_schema": "aperio/oauth_grant/v1",
		"provider":      provider,
	})
	claims = append(claims,
		sdkclaims.Exists(app, source),
		sdkclaims.Exists(grant, source),
		sdkclaims.Relation(finding, "concerns_oauth_app", app, source),
		sdkclaims.Relation(finding, "concerns_oauth_grant", grant, source),
		sdkclaims.Relation(grant, "authorized_app", app, source),
		sdkclaims.Relation(app, "observed_by", integration, source),
		sdkclaims.Attribute(app, "provider", provider, source),
		sdkclaims.Attribute(app, "externalAppId", appID, source),
		sdkclaims.Attribute(app, "displayName", appName, source),
	)
	for _, attr := range []struct {
		predicate string
		keys      []string
		subject   cerebroclient.EntityRef
	}{
		{"riskScore", []string{"oauthRiskScore", "riskScore"}, app},
		{"criticality", []string{"oauthAppCriticality", "criticality", "severity"}, app},
		{"riskReason", []string{"oauthRiskReason", "riskReason"}, app},
		{"clientType", []string{"oauthClientType", "clientType"}, app},
		{"status", []string{"oauthGrantStatus", "status"}, grant},
		{"scopeCount", []string{"oauthScopeCount", "scopeCount"}, grant},
		{"lastObservedAt", []string{"oauthGrantLastObservedAt", "lastObservedAt"}, grant},
		{"anonymous", []string{"oauthAnonymous", "anonymous"}, grant},
		{"nativeApp", []string{"oauthNativeApp", "nativeApp"}, grant},
	} {
		if value := firstStringFromRecord(record, attr.keys...); value != "" {
			claims = append(claims, sdkclaims.Attribute(attr.subject, attr.predicate, value, source))
		}
	}
	if userID != "" {
		userLabel := firstString(record["oauthUserDisplayName"], record["userDisplayName"], record["oauthUserEmail"], record["userEmail"], record["actor"], userID)
		user := Ref(tenantID, input.RuntimeID, "identity", provider+":"+userID, userLabel)
		claims = append(claims,
			sdkclaims.Exists(user, source),
			sdkclaims.Relation(user, "has_oauth_grant", grant, source),
			sdkclaims.Relation(grant, "granted_by", user, source),
		)
		if email := firstString(record["oauthUserEmail"], record["userEmail"], record["actor"]); email != "" {
			claims = append(claims, sdkclaims.Attribute(user, "email", email, source))
		}
	}
	families := map[string]string{}
	for _, scope := range firstStringSlice(record["oauthScopes"], record["scopes"], record["scope"]) {
		scopeRef := Ref(tenantID, input.RuntimeID, "oauth_scope", provider+":"+scope, shortOAuthScope(scope))
		claims = append(claims,
			sdkclaims.Exists(scopeRef, source),
			sdkclaims.Relation(grant, "has_scope", scopeRef, source),
			sdkclaims.Attribute(scopeRef, "scope", scope, source),
		)
		if family, label := oauthScopeResourceFamily(scope); family != "" {
			families[family] = label
			claims = append(claims, sdkclaims.Attribute(scopeRef, "resourceFamily", family, source))
		}
	}
	familyKeys := make([]string, 0, len(families))
	for family := range families {
		familyKeys = append(familyKeys, family)
	}
	sort.Strings(familyKeys)
	for _, family := range familyKeys {
		resource := Ref(tenantID, input.RuntimeID, "resource_family", provider+":"+family, families[family])
		claims = append(claims,
			sdkclaims.Exists(resource, source),
			sdkclaims.Relation(app, "accesses", resource, source),
		)
	}
	return claims
}

func BuildProto(input BuildInput) ([]*cerebrov1.Claim, error) {
	claims, err := Build(input)
	if err != nil {
		return nil, err
	}
	return cerebroclient.ClaimsToProto(claims), nil
}

func Ref(organizationID, runtimeID, entityType, externalID, label string) cerebroclient.EntityRef {
	encodedExternalID := EncodeExternalID(externalID)
	return cerebroclient.EntityRef{
		URN:        strings.Join([]string{"urn", "cerebro", organizationID, "runtime", runtimeID, entityType, encodedExternalID}, ":"),
		EntityType: entityType,
		Label:      label,
	}
}

// EncodeExternalID preserves Aperio's historical URN segment encoding, where a
// space maps to '-'. It delegates to the SDK's legacy encoder; switching to the
// canonical percent encoder would orphan Cerebro URNs already persisted by
// Aperio.
func EncodeExternalID(value string) string {
	return sdkclaims.EncodeExternalIDLegacy(value)
}

func claimSource(payload Payload, attributes map[string]string) sdkclaims.Source {
	return sdkclaims.Source{
		SourceEventID: firstString(payload.Record["sourceEventId"]),
		ObservedAt:    payload.OccurredAt,
		Attributes:    attributes,
	}
}

func firstString(values ...any) string {
	for _, value := range values {
		switch typed := value.(type) {
		case string:
			if trimmed := strings.TrimSpace(typed); trimmed != "" {
				return trimmed
			}
		case json.Number:
			if string(typed) != "" {
				return string(typed)
			}
		case bool:
			return strconv.FormatBool(typed)
		case int:
			return strconv.Itoa(typed)
		case int64:
			return strconv.FormatInt(typed, 10)
		case float64:
			return strconv.FormatFloat(typed, 'f', -1, 64)
		}
	}
	return ""
}

func firstStringFromRecord(record map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := firstString(record[key]); value != "" {
			return value
		}
	}
	return ""
}

func firstStringSlice(values ...any) []string {
	for _, value := range values {
		out := []string{}
		seen := map[string]struct{}{}
		switch typed := value.(type) {
		case []string:
			for _, item := range typed {
				appendUniqueString(&out, seen, item)
			}
		case []any:
			for _, item := range typed {
				appendUniqueString(&out, seen, firstString(item))
			}
		case string:
			for _, item := range strings.FieldsFunc(typed, func(r rune) bool {
				return r == ',' || r == ';' || r == '|'
			}) {
				appendUniqueString(&out, seen, item)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

func appendUniqueString(out *[]string, seen map[string]struct{}, value string) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return
	}
	key := strings.ToLower(trimmed)
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}
	*out = append(*out, trimmed)
}

func shortOAuthScope(scope string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(scope), "/")
	if trimmed == "" {
		return "OAuth scope"
	}
	parts := strings.Split(trimmed, "/")
	return parts[len(parts)-1]
}

func oauthScopeResourceFamily(scope string) (string, string) {
	normalized := strings.ToLower(strings.TrimSpace(scope))
	switch {
	case normalized == "https://mail.google.com/" || strings.Contains(normalized, "gmail"):
		return "gmail_mailbox", "Gmail mailbox"
	case strings.Contains(normalized, "/auth/drive"):
		return "google_drive", "Google Drive"
	case strings.Contains(normalized, "admin") || strings.Contains(normalized, "directory"):
		return "google_admin_directory", "Google Admin Directory"
	case strings.Contains(normalized, "cloud-platform") || strings.Contains(normalized, "bigquery"):
		return "google_cloud_data", "Google Cloud data"
	case strings.Contains(normalized, "calendar"):
		return "google_calendar", "Google Calendar"
	case strings.Contains(normalized, "repo") || strings.Contains(normalized, "organization") || strings.Contains(normalized, "members"):
		return "github_org_repo", "GitHub organization and repositories"
	case strings.Contains(normalized, "channels") || strings.Contains(normalized, "files") || strings.Contains(normalized, "users"):
		return "slack_workspace_data", "Slack workspace data"
	default:
		return "", ""
	}
}

func schemaVersion(kind string) string {
	switch strings.ToUpper(strings.TrimSpace(kind)) {
	case "FINDING", "FINDING_CREATED", "FINDING_UPDATED", "FINDING_RESOLVED":
		return "aperio/finding/v1"
	case "SIEM_TEST":
		return "aperio/siem_test/v1"
	default:
		return "aperio/event/v1"
	}
}
