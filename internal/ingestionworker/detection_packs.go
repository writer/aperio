package ingestionworker

// DetectionPack is a versioned, curated bundle of built-in finding rules
// scoped to a provider and a coherent threat surface (admin-state,
// OAuth, mailbox abuse, repo hygiene, ...). Packs are how Aperio
// communicates coverage to operators: instead of a flat list of 16+
// toggles, the UI groups by pack so a buyer can answer "what does
// Aperio detect on Google Workspace for mailbox exfiltration?" in one
// glance.
//
// Pack IDs are stable contracts; once a pack ships, never change its
// ID. Bump Version on every content change (semver). Description should
// read like a one-line analyst-facing capability statement.
type DetectionPack struct {
	ID          string
	Provider    string
	Name        string
	Description string
	Version     string
}

// DetectionPacks is the registry of every pack the worker knows about.
// Every RuleCatalogEntry.PackID must point into this table; the parity
// test in detection_packs_test.go pins the contract.
var DetectionPacks = []DetectionPack{
	{
		ID:          "aperio.github.core.v1",
		Provider:    "GITHUB",
		Name:        "GitHub repository hygiene",
		Description: "Public repository creation, branch protection bypass, and personal access token misuse on GitHub.",
		Version:     "1.0.0",
	},
	{
		ID:          "aperio.slack.core.v1",
		Provider:    "SLACK",
		Name:        "Slack workspace access",
		Description: "Multi-factor authentication state and external-collaborator access events on Slack.",
		Version:     "1.0.0",
	},
	{
		ID:          "aperio.okta.core.v1",
		Provider:    "OKTA",
		Name:        "Okta identity threats",
		Description: "Privileged role assignment, MFA factor reset, password policy weakening, and suspicious sign-in signals from Okta.",
		Version:     "1.0.0",
	},
	{
		ID:          "aperio.google_workspace.identity.v1",
		Provider:    "GOOGLE_WORKSPACE",
		Name:        "Google Workspace identity & admin",
		Description: "Super-admin and delegated-admin grants, admin MFA enforcement, and admin recovery-email risk in Google Workspace.",
		Version:     "1.0.0",
	},
	{
		ID:          "aperio.google_workspace.mail.v1",
		Provider:    "GOOGLE_WORKSPACE",
		Name:        "Google Workspace mailbox exfiltration",
		Description: "Mail forwarding, mailbox delegation, send-as, and legacy IMAP/SMTP auth paths attackers use to siphon Gmail.",
		Version:     "1.0.0",
	},
	{
		ID:          "aperio.google_workspace.drive.v1",
		Provider:    "GOOGLE_WORKSPACE",
		Name:        "Google Workspace Drive sharing & OAuth",
		Description: "External Drive sharing, risky OAuth grants, and mass-download exfiltration patterns in Google Workspace.",
		Version:     "1.0.0",
	},
}

// DetectionPackByID returns the pack with the given ID, or false if no
// pack matches. The API uses this to validate referenced pack IDs and
// to hydrate the rules under each pack for the operator UI.
func DetectionPackByID(id string) (DetectionPack, bool) {
	for _, pack := range DetectionPacks {
		if pack.ID == id {
			return pack, true
		}
	}
	return DetectionPack{}, false
}

// RulesInPack returns every RuleCatalog entry that names the given pack
// ID, preserving catalog display order. An unknown pack returns an empty slice.
func RulesInPack(packID string) []RuleCatalogEntry {
	out := make([]RuleCatalogEntry, 0, 4)
	for _, entry := range RuleCatalog {
		if entry.PackID == packID {
			out = append(out, entry)
		}
	}
	return out
}
