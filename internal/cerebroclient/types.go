package cerebroclient

type SourceRuntime struct {
	ID       string            `json:"id,omitempty"`
	SourceID string            `json:"source_id"`
	TenantID string            `json:"tenant_id"`
	Config   map[string]string `json:"config,omitempty"`
}

type EntityRef struct {
	URN        string `json:"urn"`
	EntityType string `json:"entity_type"`
	Label      string `json:"label"`
}

type Claim struct {
	ID            string            `json:"id,omitempty"`
	SubjectURN    string            `json:"subject_urn"`
	SubjectRef    EntityRef         `json:"subject_ref"`
	Predicate     string            `json:"predicate"`
	ObjectURN     string            `json:"object_urn,omitempty"`
	ObjectRef     *EntityRef        `json:"object_ref,omitempty"`
	ObjectValue   string            `json:"object_value,omitempty"`
	ClaimType     string            `json:"claim_type"`
	Status        string            `json:"status"`
	SourceEventID string            `json:"source_event_id,omitempty"`
	ObservedAt    string            `json:"observed_at"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

type WriteClaimsRequest struct {
	RuntimeID       string  `json:"runtime_id"`
	Claims          []Claim `json:"claims"`
	ReplaceExisting bool    `json:"replace_existing,omitempty"`
}

type WriteClaimsResponse struct {
	ClaimsWritten          uint32 `json:"claims_written"`
	EntitiesUpserted       uint32 `json:"entities_upserted"`
	RelationLinksProjected uint32 `json:"relation_links_projected"`
	ClaimsRetracted        uint32 `json:"claims_retracted"`
}

type sourceRuntimeResponse struct {
	Runtime *SourceRuntime `json:"runtime"`
}
