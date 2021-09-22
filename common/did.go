package common

type DIDDocument struct {
	Context              []interface{} `json:"@context"`
	ID                   string        `json:"id"`
	VerificationMethod   []interface{} `json:"verificationMethod"`
	AssertionMethod      []interface{} `json:"assertionMethod"`
	Authentication       []interface{} `json:"authentication"`
	CapabilityInvocation []interface{} `json:"capabilityInvocation"`
	CapabilityDelegation []interface{} `json:"capabilityDelegation"`
	KeyAgreement         []interface{} `json:"keyAgreement"`
}
