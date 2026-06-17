package cerebroclaims

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	cerebrov1 "github.com/writer/aperio/gen/cerebro/v1"
	"github.com/writer/aperio/internal/cerebroclient"
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
		existsClaim(finding, input.Payload, attributes),
		existsClaim(target, input.Payload, map[string]string{"provider": provider}),
		existsClaim(integration, input.Payload, map[string]string{"provider": provider}),
		relationClaim(finding, "affects", target, input.Payload),
		relationClaim(finding, "observed_by", integration, input.Payload),
		attributeClaim(finding, "title", title, input.Payload),
		attributeClaim(finding, "provider", provider, input.Payload),
	}
	for _, key := range []string{"severity", "riskScore", "status", "ruleId"} {
		if value := firstString(input.Payload.Record[key]); value != "" {
			claims = append(claims, attributeClaim(finding, key, value, input.Payload))
		}
	}
	if description := firstString(input.Payload.Record["description"]); description != "" {
		claims = append(claims, attributeClaim(finding, "description", description, input.Payload))
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

func EncodeExternalID(value string) string {
	const upperHex = "0123456789ABCDEF"
	var builder strings.Builder
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'A' && character <= 'Z') ||
			(character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			character == '-' ||
			character == '_' ||
			character == '.' ||
			character == '!' ||
			character == '~' ||
			character == '*' ||
			character == '\'' ||
			character == '(' ||
			character == ')' {
			builder.WriteByte(character)
			continue
		}
		if character == ' ' {
			builder.WriteByte('-')
			continue
		}
		builder.WriteByte('%')
		builder.WriteByte(upperHex[character>>4])
		builder.WriteByte(upperHex[character&0x0f])
	}
	return builder.String()
}

func claimBase(payload Payload, attributes map[string]string) cerebroclient.Claim {
	return cerebroclient.Claim{
		Status:        "asserted",
		SourceEventID: firstString(payload.Record["sourceEventId"]),
		ObservedAt:    payload.OccurredAt,
		Attributes:    attributes,
	}
}

func existsClaim(subject cerebroclient.EntityRef, payload Payload, attributes map[string]string) cerebroclient.Claim {
	claim := claimBase(payload, attributes)
	claim.SubjectURN = subject.URN
	claim.SubjectRef = subject
	claim.Predicate = "exists"
	claim.ClaimType = "existence"
	return claim
}

func attributeClaim(subject cerebroclient.EntityRef, predicate string, value string, payload Payload) cerebroclient.Claim {
	claim := claimBase(payload, nil)
	claim.SubjectURN = subject.URN
	claim.SubjectRef = subject
	claim.Predicate = predicate
	claim.ObjectValue = value
	claim.ClaimType = "attribute"
	return claim
}

func relationClaim(subject cerebroclient.EntityRef, predicate string, object cerebroclient.EntityRef, payload Payload) cerebroclient.Claim {
	claim := claimBase(payload, nil)
	claim.SubjectURN = subject.URN
	claim.SubjectRef = subject
	claim.Predicate = predicate
	claim.ObjectURN = object.URN
	claim.ObjectRef = &object
	claim.ClaimType = "relation"
	return claim
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
