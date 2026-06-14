package ingestionworker

import (
	"sort"
	"strings"
)

// Canonical Finding tags. Tags are an additive, queryable categorization
// of *what kind of risk* a finding represents — independent of which
// provider produced it. They power cross-provider grouping in the UI
// ("show me everything that weakens MFA"), feed compliance mappings
// (e.g. CIS 6.5 = `auth.mfa_weakened`), and let custom rule authors
// inherit a coherent classification without inventing one per provider.
//
// Tag shape is `<domain>.<descriptor>`. Lowercase, snake_case. Keep the
// set small and merge before inventing: 13 tags here covers every
// built-in evaluator in this package. Add a new one only when no
// existing tag fits.
const (
	// auth.* — anything that weakens or bypasses the authentication
	// posture for a real user account.
	TagAuthMFAWeakened     = "auth.mfa_weakened"
	TagAuthPassword        = "auth.password"
	TagAuthSuspiciousLogin = "auth.suspicious_signin"
	TagAuthLegacyProtocol  = "auth.legacy_protocol"
	TagAuthAccountRecovery = "auth.account_recovery"

	// iam.* — identity / privilege topology changes.
	TagIAMPrivilegeEscalation = "iam.privilege_escalation"

	// data.* — surfaces or paths through which tenant data can leave
	// the boundary.
	TagDataExternalShare  = "data.external_share"
	TagDataPublicExposure = "data.public_exposure"
	TagDataAccess         = "data.access"

	// policy.* — security policy was relaxed (independent of any
	// specific user action that exploited it).
	TagPolicyWeakened = "policy.weakened"

	// oauth.* — third-party OAuth client risk.
	TagOAuthRiskyGrant = "oauth.risky_grant"

	// email.* — mailbox-level abuse vectors.
	TagEmailForwarding = "email.forwarding"
	TagEmailDelegation = "email.delegation"
)

// AllTags is the registry — keep in sync with the constants above. It
// lets the test suite assert that every constant is unique and gives the
// API surface a stable enumeration to validate against if/when we add a
// "filter findings by tag" UI.
var AllTags = []string{
	TagAuthMFAWeakened,
	TagAuthPassword,
	TagAuthSuspiciousLogin,
	TagAuthLegacyProtocol,
	TagAuthAccountRecovery,
	TagIAMPrivilegeEscalation,
	TagDataExternalShare,
	TagDataPublicExposure,
	TagDataAccess,
	TagPolicyWeakened,
	TagOAuthRiskyGrant,
	TagEmailForwarding,
	TagEmailDelegation,
}

// normalizeTags lowercases, trims, deduplicates and sorts a tag slice.
// Used at the boundary so the DB always stores a canonical form
// regardless of which evaluator produced it.
func normalizeTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(tags))
	out := make([]string, 0, len(tags))
	for _, raw := range tags {
		normalized := strings.ToLower(strings.TrimSpace(raw))
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out
}
