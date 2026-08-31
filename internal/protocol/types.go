// Package protocol contains the wire-level types for the MVP event schema.
package protocol

const AppDeclarationKind int = 30078

// AppDeclaration is the validated, platform-specific data extracted from a
// parameterised replaceable Nostr app declaration.
type AppDeclaration struct {
	AppID         string
	Publisher     string
	Repository    string
	Version       string
	Commit        string
	ManifestHash  string
	ContentHash   string
	Category      string
	Name          string
	Description   string
	Architectures []string
}
