package cerebroclient

import "github.com/writer/cerebro/sdk/go/cerebroapi"

// Proto claim request/response types re-exported from the Cerebro SDK so
// Aperio call sites keep using the cerebroclient facade. The WriteProtoClaims
// and ListProtoClaims methods are promoted from the embedded *cerebroapi.Client.
type (
	WriteProtoClaimsRequest = cerebroapi.WriteProtoClaimsRequest
	ListProtoClaimsResponse = cerebroapi.ListProtoClaimsResponse
)

// Proto claim conversion helpers re-exported from the Cerebro SDK.
var (
	ClaimToProto    = cerebroapi.ClaimToProto
	ClaimsToProto   = cerebroapi.ClaimsToProto
	ClaimFromProto  = cerebroapi.ClaimFromProto
	ClaimsFromProto = cerebroapi.ClaimsFromProto
)
