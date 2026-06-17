package cerebroclaims

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
